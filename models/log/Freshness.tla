----------------------------- MODULE Freshness -----------------------------
(* Freshness (trust/log, lease.go): a member cut off from a removal refuses
   the removed one once its leases run out, under bounded clock skew.

   Attacker (docs/02-threat-model.md): the log-transport attacker, who keeps
   the removal from the member N and delivers it any lease, or none, at any
   time; and up to M - 1 admin devices that vouch dishonestly, or were
   removed, and so vouch for the old head whenever asked, dated as they like.

   Abstractions: the removal is written at time 0 and an honest admin device
   v vouches for the head without it until Learn[v], with it from then on; a
   lease naming that head is not on N's chain and counts for nothing. Time
   is whole steps; Offset is each device's clock against real time, at most
   D either way, with 2·D within MaxLeaseSkew, so an honest lease is never
   dated too far ahead. Being stale is refusing every member but the admin
   devices, the removed one among them. *)
EXTENDS Integers, FiniteSets

CONSTANTS
  Vouchers,   \* the admin devices N's state names
  Dishonest,  \* those of them the attacker holds
  M,          \* how many must vouch (State.Vouchers)
  TTL,        \* the freshness TTL
  Skew,       \* MaxLeaseSkew
  D,          \* the most a clock is off
  Horizon     \* the last step checked

ASSUME /\ Dishonest \subseteq Vouchers
       /\ Cardinality(Dishonest) < M /\ M <= Cardinality(Vouchers)
       /\ 2 * D <= Skew

Honest == Vouchers \ Dishonest
Never == Horizon + 1

VARIABLES
  now,      \* real time
  offset,   \* device -> its clock's offset; N is "N"
  learn,    \* honest admin device -> when it holds the removal
  newest    \* honest admin device -> the issue date of the newest lease for
            \* the old head N holds from it, or None

None == -1000

vars == <<now, offset, learn, newest>>

Clock(d) == now + offset[d]

(* CheckLease and Freshness at N's clock: a lease counts while dated no
   further than Skew ahead and younger than TTL. *)
Counts(issued) == issued # None /\ issued <= Clock("N") + Skew /\ Clock("N") < issued + TTL

(* The attacker's admin devices date a lease at N's clock whenever asked. *)
Vouching == Cardinality({h \in Honest : Counts(newest[h])}) + Cardinality(Dishonest)

Fresh == Vouching >= M

Init ==
  /\ now = 0
  /\ offset \in [Vouchers \cup {"N"} -> -D..D]
  /\ learn \in [Honest -> 0..Never]
  /\ newest = [h \in Honest |-> None]

(* An honest admin device signs a lease for the head it holds, and the
   attacker hands it to N; one for the head with the removal N cannot use. *)
Lease(h) ==
  /\ now < learn[h]
  /\ newest' = [newest EXCEPT ![h] = Clock(h)]
  /\ UNCHANGED <<now, offset, learn>>

Tick ==
  /\ now < Horizon
  /\ now' = now + 1
  /\ UNCHANGED <<offset, learn, newest>>

Next == Tick \/ \E h \in Honest : Lease(h)

Spec == Init /\ [][Next]_vars

(* The time from which fewer than the honest devices N still needs vouch
   for the old head. *)
Needed == M - Cardinality(Dishonest)
Cutoff == CHOOSE t \in 0..Never : /\ Cardinality({h \in Honest : learn[h] > t}) < Needed
                                  /\ \A u \in 0..(t - 1) : Cardinality({h \in Honest : learn[h] > u}) >= Needed

(* N refuses the removed member from TTL past the last lease before the
   cutoff, plus what two clocks can be apart. *)
RefusedAtTTL == Fresh => now < Cutoff + TTL + 2 * D - 1

=============================================================================
