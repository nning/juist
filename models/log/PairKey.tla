------------------------------ MODULE PairKey ------------------------------
(* The pair key's exchange as a state machine (internal/pairkey, pair.go and
   store.go): a leader and a follower moving from the group key to keys of
   their own, generation by generation, across epoch bumps and restarts.

   Attacker (docs/02-threat-model.md): the network observer, who drops,
   repeats and reorders every message, and blocks handshakes so that the
   leader probes the other key; messages are signed, so nothing is forged.
   pairkey*.pv proves the keys secret; this model asks what each side uses.

   Abstractions: a key is named by its generation, epoch and the two
   ciphertexts that made it, so two sides derived alike exactly when their
   names agree; both sides read one epoch, the lower they announce; pacing
   is left out. A store reset is a fresh store ID, which the peer learns from
   an announcement; a restore puts a side back to what it last kept. The
   names say which function each operator stands for. *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  MaxGen,        \* the generations the leader starts, at most
  MaxEpoch,      \* the epochs, from 1
  MaxIds,        \* ciphertexts and store IDs drawn, at most
  Resets,        \* whether a side gives its pairs up under a new store
  Restores       \* whether a side is put back to what it last kept

None == [n |-> 0, e |-> 0, l |-> 0, f |-> 0]
IsNone(g) == g.n = 0

VARIABLES
  L, F,           \* the two sides' Pair, and their stores' ID and view
  net,            \* every message sent: any is delivered, again, or never
  epoch,
  ids,            \* the last ID drawn
  keptF           \* what the follower last kept, for a restore

vars == <<L, F, net, epoch, ids, keptF>>

Group(e) == [n |-> 0, e |-> e, l |-> 0, f |-> 0]

FreshPairL(store, peer, last) ==
  [cur |-> None, next |-> None, pend |-> None, last |-> last, flip |-> FALSE, redo |-> FALSE,
   prev |-> None, store |-> store, peer |-> peer, slast |-> last]
FreshPairF(store, peer) ==
  [cur |-> None, offered |-> None, prev |-> None, store |-> store, peer |-> peer]

Init ==
  /\ L = FreshPairL(1, 2, 0)
  /\ F = FreshPairF(2, 1)
  /\ net = {}
  /\ epoch = 1
  /\ ids = 2
  /\ keptF = F

(* Pair.key: what each side's handshakes mix in. *)
KeyL(flip) == IF ~IsNone(L.next) /\ ~flip THEN L.next ELSE IF IsNone(L.cur) THEN Group(epoch) ELSE L.cur
KeyF == IF IsNone(F.cur) THEN Group(epoch) ELSE F.cur

(* Pair.outgoing. *)
OutL ==
  CASE ~IsNone(L.next) -> [from |-> "L", store |-> L.store, to |-> L.peer, gen |-> L.next.n, epoch |-> L.next.e,
                            ct |-> 0, check |-> L.next, use |-> L.next.n]
    [] ~IsNone(L.pend) -> [from |-> "L", store |-> L.store, to |-> L.peer, gen |-> L.pend.n, epoch |-> L.pend.e,
                            ct |-> L.pend.l, check |-> None, use |-> L.cur.n]
    [] OTHER           -> [from |-> "L", store |-> L.store, to |-> L.peer, gen |-> L.cur.n, epoch |-> 0,
                            ct |-> 0, check |-> None, use |-> L.cur.n]
OutF ==
  IF ~IsNone(F.offered)
  THEN [from |-> "F", store |-> F.store, to |-> F.peer, gen |-> F.offered.n, epoch |-> F.offered.e,
        ct |-> F.offered.f, check |-> F.offered, use |-> F.cur.n]
  ELSE [from |-> "F", store |-> F.store, to |-> F.peer, gen |-> F.cur.n, epoch |-> 0,
        ct |-> 0, check |-> None, use |-> F.cur.n]

SendL == /\ net' = net \cup {OutL} /\ UNCHANGED <<L, F, epoch, ids, keptF>>
SendF == /\ net' = net \cup {OutF} /\ UNCHANGED <<L, F, epoch, ids, keptF>>

Max(a, b) == IF a >= b THEN a ELSE b

(* Pair.advance: the leader starts a generation where it has none in the
   pair's epoch. *)
Advance ==
  /\ IsNone(L.next)
  /\ ~(~IsNone(L.pend) /\ L.pend.e >= epoch)
  /\ ~(IsNone(L.pend) /\ ~IsNone(L.cur) /\ L.cur.e >= epoch /\ ~L.redo)
  /\ Max(L.last, L.cur.n) < MaxGen
  /\ ids < MaxIds
  /\ LET n == Max(L.last, L.cur.n) + 1
     IN L' = [L EXCEPT !.last = n, !.slast = Max(@, n), !.redo = FALSE,
                       !.pend = [n |-> n, e |-> epoch, l |-> ids + 1, f |-> 0]]
  /\ ids' = ids + 1
  /\ UNCHANGED <<F, net, epoch, keptF>>

(* Pair.use: g becomes the key in use, the one it replaces kept as Prev. *)
UseL(p, g) == [p EXCEPT !.prev = IF IsNone(p.cur) THEN @ ELSE p.cur, !.cur = g]

(* Store.Take and Pair.takeAsLeader. *)
TakeL(m) ==
  /\ m.from = "F" /\ m.store = L.peer /\ m.to = L.store
  /\ Max(m.gen, m.use) <= L.slast
  /\ LET last  == Max(L.last, Max(m.gen, m.use))
         redo  == L.redo \/ (IsNone(L.next) /\ IsNone(L.pend) /\ (m.use > L.cur.n \/ (m.use = 0 /\ ~IsNone(L.cur))))
         taken == ~IsNone(L.pend) /\ m.gen = L.pend.n /\ m.ct # 0
         key   == [n |-> L.pend.n, e |-> L.pend.e, l |-> L.pend.l, f |-> m.ct]
         p1    == IF taken
                  THEN [L EXCEPT !.last = last, !.redo = redo, !.pend = None,
                                 !.next = IF m.check = key THEN key ELSE @,
                                 !.flip = IF m.check = key THEN FALSE ELSE @]
                  ELSE [L EXCEPT !.last = last, !.redo = redo]
     IN L' = IF ~IsNone(p1.next) /\ m.use = p1.next.n
             THEN [UseL(p1, p1.next) EXCEPT !.next = None, !.flip = FALSE]
             ELSE p1
  /\ UNCHANGED <<F, net, epoch, ids, keptF>>

(* Store.Take and Pair.takeAsFollower. *)
TakeF(m) ==
  /\ m.from = "L" /\ m.store = F.peer /\ m.to = F.store
  /\ LET offer == m.ct # 0 /\ m.gen > F.cur.n /\ (IsNone(F.offered) \/ m.gen > F.offered.n)
         p1    == IF offer
                  THEN [F EXCEPT !.offered = [n |-> m.gen, e |-> m.epoch, l |-> m.ct, f |-> ids + 1]]
                  ELSE F
     IN /\ offer => ids < MaxIds
        /\ ids' = IF offer THEN ids + 1 ELSE ids
        /\ F' = IF ~IsNone(p1.offered) /\ m.use = p1.offered.n /\ m.check = p1.offered
                THEN [UseL(p1, p1.offered) EXCEPT !.offered = None]
                ELSE p1
  /\ UNCHANGED <<L, net, epoch, keptF>>

(* Store.Probe: the leader's tunnel is down while its commit is unconfirmed,
   so it tries the other key. *)
Probe ==
  /\ ~IsNone(L.next)
  /\ L' = [L EXCEPT !.flip = ~@]
  /\ UNCHANGED <<F, net, epoch, ids, keptF>>

Bump ==
  /\ epoch < MaxEpoch
  /\ epoch' = epoch + 1
  /\ UNCHANGED <<L, F, net, ids, keptF>>

(* Store.Reset, the follower's or the leader's: every pair given up under a
   new ID, which the peer learns by announcement; a store that kept nothing
   gives nothing up. *)
KeptNothingF == IsNone(F.cur) /\ IsNone(F.offered)
KeptNothingL == IsNone(L.cur) /\ IsNone(L.next) /\ IsNone(L.pend) /\ L.slast = 0

ResetF ==
  /\ Resets /\ ids < MaxIds /\ ~KeptNothingF
  /\ F' = FreshPairF(ids + 1, F.peer)
  /\ ids' = ids + 1
  /\ UNCHANGED <<L, net, epoch, keptF>>
ResetL ==
  /\ Resets /\ ids < MaxIds /\ ~KeptNothingL
  /\ L' = FreshPairL(ids + 1, L.peer, 0)
  /\ ids' = ids + 1
  /\ UNCHANGED <<F, net, epoch, keptF>>

(* An announcement names the peer's store; a pair bound to another starts
   over (Store.pair), keeping the store's last generation. *)
AnnounceToL ==
  /\ L.peer # F.store
  /\ L' = FreshPairL(L.store, F.store, L.slast)
  /\ UNCHANGED <<F, net, epoch, ids, keptF>>
AnnounceToF ==
  /\ F.peer # L.store
  /\ F' = FreshPairF(F.store, L.store)
  /\ UNCHANGED <<L, net, epoch, ids, keptF>>

(* "Kept before told": the follower writes its store, and later a restore
   puts it back to that. *)
KeepF == /\ Restores /\ keptF' = F /\ UNCHANGED <<L, F, net, epoch, ids>>
RestoreF == /\ Restores /\ F' = keptF /\ UNCHANGED <<L, net, epoch, ids, keptF>>

Next ==
  \/ SendL \/ SendF \/ Advance \/ Probe \/ Bump
  \/ \E m \in net : TakeL(m) \/ TakeF(m)
  \/ ResetF \/ ResetL \/ AnnounceToL \/ AnnounceToF
  \/ KeepF \/ RestoreF

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* The properties. *)

Bound == L.peer = F.store /\ F.peer = L.store

(* "Every key either side may use is a pair key or the group key, never
   none", and the follower's is one the leader tries: blocking handshakes
   never take a bound pair apart for good. *)
FollowerKeyIsOneTheLeaderTries == Bound => KeyF \in {KeyL(FALSE), KeyL(TRUE)}

(* Both sides on a generation derived it alike. *)
NoKeyOfOneSide == Bound /\ ~IsNone(F.cur) /\ ~IsNone(L.cur) /\ F.cur.n = L.cur.n => F.cur = L.cur

(* A stale or repeated message moves the follower's key nothing back, while
   it is bound to one store of the leader's. *)
NothingMovesBack ==
  [][F.store = F'.store /\ F.peer = F'.peer /\ ~(Restores /\ F' = keptF) => F'.cur.n >= F.cur.n]_vars

(* No generation number is used twice in a store: an offer the leader
   starts lies past every generation the store has started. *)
NoGenerationTwice ==
  [][L.store = L'.store /\ ~IsNone(L'.pend) /\ L'.pend # L.pend => L'.pend.n > L.slast]_vars

=============================================================================
