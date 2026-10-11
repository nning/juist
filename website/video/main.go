// Command video renders the tour in this directory, frame by frame in
// headless Chrome, into MP4 and WebM with ffmpeg.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func main() {
	out := flag.String("out", "../../build/video", "output directory")
	casts := flag.String("casts", "../static", "directory holding the casts")
	chrome := flag.String("chrome", "chrome", "Chrome to run")
	fps := flag.Int("fps", 30, "frames a second")
	still := flag.String("still", "", "write PNGs at these comma-separated seconds instead of a video")
	from := flag.Float64("from", 0, "first second to render")
	to := flag.Float64("to", 0, "last second to render; 0 for the end")
	verbose := flag.Bool("v", false, "show Chrome's log")
	flag.Parse()
	log.SetFlags(0)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(".")))
	mux.Handle("/fonts/", http.StripPrefix("/fonts/", http.FileServer(http.Dir("../static/fonts"))))
	mux.Handle("/casts/", http.StripPrefix("/casts/", http.FileServer(http.Dir(*casts))))
	mux.HandleFunc("/wordmark.svg", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "../../design/logo/wordmark.svg")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, mux)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(*chrome),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.WindowSize(1920, 1080),
	)
	if *verbose {
		opts = append(opts, chromedp.CombinedOutput(os.Stderr))
	}
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()

	var meta struct{ Duration float64 }
	err = chromedp.Run(ctx,
		emulation.SetDeviceMetricsOverride(1920, 1080, 1, false),
		chromedp.Navigate("http://"+ln.Addr().String()+"/"),
		chromedp.Evaluate(`window.videoReady`, &meta, awaitPromise),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tour: %.1fs", meta.Duration)

	frame := func(t float64) ([]byte, error) {
		var png []byte
		err := chromedp.Run(ctx,
			chromedp.Evaluate(fmt.Sprintf("seek(%f)", t), nil, awaitPromise),
			chromedp.ActionFunc(func(ctx context.Context) (err error) {
				png, err = page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatPng).Do(ctx)
				return err
			}),
		)
		return png, err
	}

	if *still != "" {
		for _, s := range strings.Split(*still, ",") {
			t, err := strconv.ParseFloat(s, 64)
			if err != nil {
				log.Fatal(err)
			}
			png, err := frame(t)
			if err != nil {
				log.Fatal(err)
			}
			name := filepath.Join(*out, fmt.Sprintf("still-%06.2f.png", t))
			if err := os.WriteFile(name, png, 0o644); err != nil {
				log.Fatal(err)
			}
			log.Print(name)
		}
		return
	}

	end := meta.Duration
	if *to > 0 && *to < end {
		end = *to
	}
	ff := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
		"-f", "image2pipe", "-framerate", strconv.Itoa(*fps), "-i", "-",
		"-map", "0", "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-pix_fmt", "yuv420p",
		"-movflags", "+faststart", filepath.Join(*out, "tour.mp4"),
		"-map", "0", "-c:v", "libvpx-vp9", "-crf", "34", "-b:v", "0", "-row-mt", "1", "-deadline", "good", "-cpu-used", "2",
		"-pix_fmt", "yuv420p", filepath.Join(*out, "tour.webm"))
	ff.Stderr = os.Stderr
	stdin, err := ff.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := ff.Start(); err != nil {
		log.Fatal(err)
	}
	start := time.Now()
	n := int((end - *from) * float64(*fps))
	for i := 0; i < n; i++ {
		png, err := frame(*from + float64(i)/float64(*fps))
		if err != nil {
			log.Fatal(err)
		}
		if _, err := stdin.Write(png); err != nil {
			log.Fatal(err)
		}
		if i%(*fps*5) == 0 {
			log.Printf("frame %d/%d (%s)", i, n, time.Since(start).Round(time.Second))
		}
	}
	stdin.Close()
	if err := ff.Wait(); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s/tour.{mp4,webm} in %s", *out, time.Since(start).Round(time.Second))
}

func awaitPromise(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }
