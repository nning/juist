// Package browsertest checks the built site in Chrome: make -C website test-browser.
package browsertest

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/device"
)

var (
	site   = flag.String("site", "", "the built site")
	chrome = flag.String("chrome", "", "Chrome's binary")
)

func browse(t *testing.T) (context.Context, string) {
	if *site == "" || *chrome == "" {
		t.Fatal("-site and -chrome are required")
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(*site)))
	t.Cleanup(srv.Close)
	ac, cancel := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(*chrome), chromedp.NoSandbox, chromedp.DisableGPU,
		chromedp.Flag("disable-dev-shm-usage", true))...)
	t.Cleanup(cancel)
	ctx, cancel := chromedp.NewContext(ac)
	t.Cleanup(cancel)
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	t.Cleanup(cancel)
	return ctx, srv.URL
}

// The menu on a phone fills the space below the header and scrolls to its last entry.
func TestMenuScrollsOnAPhone(t *testing.T) {
	ctx, url := browse(t)
	for _, lang := range []string{"en", "de"} {
		var got struct {
			Top, Bottom, Header, Viewport, Client, Scroll, ScrolledTo float64
		}
		err := chromedp.Run(ctx,
			chromedp.Emulate(device.Pixel5),
			chromedp.Navigate(url+"/"+lang+"/docs/"),
			chromedp.Click("[data-menu]", chromedp.ByQuery),
			chromedp.Evaluate(`(() => {
				const s = document.querySelector(".sidebar"), r = s.getBoundingClientRect();
				s.scrollTop = s.scrollHeight;
				return {Top: r.top, Bottom: r.bottom, Header: document.querySelector(".site-header").getBoundingClientRect().bottom,
					Viewport: innerHeight, Client: s.clientHeight, Scroll: s.scrollHeight, ScrolledTo: s.scrollTop};
			})()`, &got),
		)
		if err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		if got.Top < got.Header-1 || got.Bottom > got.Viewport+1 {
			t.Errorf("%s: the menu spans %.0f to %.0f, want within %.0f to %.0f", lang, got.Top, got.Bottom, got.Header, got.Viewport)
		}
		if got.Scroll > got.Client && got.ScrolledTo < got.Scroll-got.Client-1 {
			t.Errorf("%s: the menu scrolls to %.0f of %.0f", lang, got.ScrolledTo, got.Scroll-got.Client)
		}
		if got.Scroll <= got.Viewport-got.Header {
			t.Errorf("%s: the menu fits the screen (%.0f of %.0f), so this test proves nothing; make the viewport smaller", lang, got.Scroll, got.Viewport-got.Header)
		}
	}
}
