-------------------------------- MODULE Log --------------------------------
(* The membership log (trust/log): validators resolving one tree of records
   from an anchor by fork choice, under an epoch floor, compacting to a
   checkpoint.

   Attacker (docs/02-threat-model.md): the log-transport attacker, who
   delivers any record to any validator in any order, or not at all; a
   compromised admin, below quorum, and an evicted one, whose keys
   (Compromised) sign anything on any record they are admins at; and a member
   that has devices compact early (residual weakness 14), which Compact
   allows whenever trust/log does unless CompactPolicy is juistd's. Admins
   sign on the head their device holds, so concurrent changes fork the log.

   Abstractions: one vote per holder; the keys in PairedKeys are one person's,
   who votes once PairNeeded of them signed, every other key its own holder.
   A record's content order (SigHash) is its srank, drawn when it is written;
   copies of one content share it and differ in hrank, their hash order. A
   record names its subject, and its state after it is its parent's with it
   applied, which a checkpoint states. A schema stop, disable records, holder
   policies changed by a record, identity rotations and the kinds that change
   no membership or authority are left out. Resolution follows resolve.go,
   forkchoice.go and orphans.go step for step: the names say which function
   each operator stands for. *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
  Keys,           \* admin keys
  PairedKeys,     \* the keys of the one holder with several
  PairNeeded,     \* how many of them must sign for its vote
  Nodes,          \* members
  Validators,     \* devices resolving the log
  Compromised,    \* admin keys the attacker holds
  GenesisAdmins,
  GenesisQuorum,
  GenesisNodes,
  MaxRecords,
  Kinds,          \* the kinds admins write
  CopiesWritten,  \* whether admins make copies; the attacker always may
  CompactPolicy,  \* "none", "any" (Authority.Compact's own guard) or "heard" (juistd's)
  AuthorTakesIn   \* whether the author's device takes its record in as it writes it

ASSUME /\ Compromised \subseteq Keys /\ GenesisAdmins \subseteq Keys /\ GenesisNodes \subseteq Nodes
       /\ PairedKeys \subseteq Keys /\ PairNeeded \in 1..2
       /\ CompactPolicy \in {"none", "any", "heard"}

VARIABLES
  rec,       \* the records written: rec[i] for i in 1..Len(rec); 0 is genesis
  store,     \* v -> the records v holds, its anchor among them
  anchor,    \* v -> the record v resolves from: genesis or a checkpoint
  floor,     \* v -> the epoch floor
  rollback,  \* v -> whether v resolved below its floor
  res,       \* v -> its resolution of what it holds, kept as it changes
  owed       \* <<v, i>>: v wrote record i and takes it in next; <<>> for none

vars == <<rec, store, anchor, floor, rollback, res, owed>>

State0 == [admins |-> GenesisAdmins, quorum |-> GenesisQuorum, nodes |-> GenesisNodes, epoch |-> 0]

NoProbe == [ok |-> FALSE, s |-> State0]

StateAt(i) == IF i = 0 THEN State0 ELSE rec[i].after

Ids == 1..Len(rec)

(* types.CountVotes: a holder's keys vote together, once. *)
HolderOf(k) == IF k \in PairedKeys THEN "pair" ELSE k
Holders == {HolderOf(k) : k \in Keys}
NeededOf(h) == IF h = "pair" THEN PairNeeded ELSE 1
Votes(s, S) == Cardinality({h \in Holders : Cardinality({k \in S \cap s.admins : HolderOf(k) = h}) >= NeededOf(h)})
Achievable(s) == Votes(s, s.admins)

(* Kinds that carry an epoch record bump the epoch (types/aum.go, kindFields). *)
Bumps(k) == k \in {"AddNode", "RemoveNode", "EpochBump"}

(* apply.go: what each kind needs of the state it applies to. *)
Applies(s, r) ==
  CASE r.kind = "AddNode"     -> r.subj \notin s.nodes
    [] r.kind = "RemoveNode"  -> r.subj \in s.nodes
    [] r.kind = "RemoveAdmin" -> r.subj \in s.admins /\ Achievable([s EXCEPT !.admins = @ \ {r.subj}]) >= s.quorum
    [] r.kind = "SetQuorum"   -> r.q >= 1 /\ r.q <= Achievable(s)
    [] r.kind = "EpochBump"   -> TRUE
    [] r.kind = "Checkpoint"  -> TRUE

(* verify.go: every signer an admin, and a quorum of votes. *)
Authorized(s, r) == r.signers \subseteq s.admins /\ Votes(s, r.signers) >= s.quorum

Valid(s, r) == Authorized(s, r) /\ Applies(s, r)

Apply(s, r) ==
  [admins |-> IF r.kind = "RemoveAdmin" THEN s.admins \ {r.subj} ELSE s.admins,
   quorum |-> IF r.kind = "SetQuorum" THEN r.q ELSE s.quorum,
   nodes  |-> CASE r.kind = "AddNode"    -> s.nodes \cup {r.subj}
                [] r.kind = "RemoveNode" -> s.nodes \ {r.subj}
                [] OTHER                 -> s.nodes,
   epoch  |-> IF Bumps(r.kind) THEN s.epoch + 1 ELSE s.epoch]

(* applyProbe: a checkpoint has nothing to reissue. *)
ProbeApplies(s, r) == r.kind = "Checkpoint" \/ Applies(s, r)
ProbeApply(s, r) == IF r.kind = "Checkpoint" THEN s ELSE Apply(s, r)

(* State.Revokes and State.alreadyRevoked. *)
Revokes(s, r) == r.kind \in {"RemoveNode", "RemoveAdmin"} \/ (r.kind = "SetQuorum" /\ r.q > s.quorum)

AlreadyRevoked(s, r) ==
  CASE r.kind = "RemoveNode"  -> r.subj \notin s.nodes
    [] r.kind = "RemoveAdmin" -> r.subj \notin s.admins
    [] r.kind = "SetQuorum"   -> s.quorum >= r.q
    [] OTHER                  -> FALSE

(* A record's content, which its SigHash covers: an epoch record's fresh
   secret sets every one apart. Copies are the records of one content. *)
Content(r) == <<r.parent, r.kind, r.subj, r.q>>
KeyOf(i) == IF i = 0 THEN <<"genesis">> ELSE rec[i].key
Copies(S, i) == IF i = 0 THEN {0} ELSE {j \in S \ {0} : rec[j].key = rec[i].key}

HRank(i) == IF i = 0 THEN 0 ELSE rec[i].hrank

(* The lowest hash stands for the copies. *)
Rep(G) == CHOOSE j \in G : \A k \in G : HRank(j) <= HRank(k)
Rec(G) == rec[Rep(G)]
ParentOf(G) == rec[Rep(G)].parent
SignersOf(G) == UNION {rec[j].signers : j \in G}

Children(S, p) == {i \in S \ {0} : rec[i].parent = p}

(* childrenOf: what hangs from any copy of G, gathered into copies. *)
ChildGroups(S, G) == {Copies(S, c) : c \in {c \in S \ {0} : rec[c].parent \in G}}

RECURSIVE SubG(_, _)
SubG(S, G) == {G} \cup UNION {SubG(S, H) : H \in ChildGroups(S, G)}

RECURSIVE SubIds(_, _)
SubIds(S, i) == {i} \cup UNION {SubIds(S, j) : j \in Children(S, i)}

RECURSIVE Ancestors(_)
Ancestors(i) == IF i = 0 THEN {0} ELSE {i} \cup Ancestors(rec[i].parent)

BranchRemoves(S, G) == {Rec(H).subj : H \in {H \in SubG(S, G) : Rec(H).kind = "RemoveAdmin"}}

(* signedRecord.undoneBy: a record of the branch at G stands only by keys in
   R, those keys taken together, its copies' signatures united. *)
StandsBy(S, G, R) ==
  R # {} /\ \E H \in SubG(S, G) : Votes(StateAt(ParentOf(H)), SignersOf(H) \ R) < StateAt(ParentOf(H)).quorum

(* The branch at G stands by keys the branch at H removes. *)
Undone(S, G, H) == StandsBy(S, G, BranchRemoves(S, H))

(* pickPrimary: a branch undone by a sibling it does not undo in turn is out
   first; the rest go by revocation, then by SigHash. Where every branch is
   out, none can be settled. *)
Ranked(s, G, H) ==
  \/ Revokes(s, Rec(G)) /\ ~Revokes(s, Rec(H))
  \/ Revokes(s, Rec(G)) = Revokes(s, Rec(H)) /\ Rec(G).srank < Rec(H).srank

(* resolve's walk, over copies, each step's losers kept with whether fork
   choice could weigh them against the winner. *)
RECURSIVE Walk(_, _, _)
Walk(S, ch, lost) ==
  LET C == ChildGroups(S, ch[Len(ch)])
  IN IF C = {} THEN <<ch, lost>>
     ELSE LET U   == [G \in C |-> [H \in C |-> Undone(S, G, H)]]
              Out == {G \in C : \E H \in C \ {G} : U[G][H] /\ ~U[H][G]}
              cyc == Out = C
              E   == IF cyc THEN C ELSE C \ Out
              s   == StateAt(Rep(ch[Len(ch)]))
              W   == CHOOSE G \in E : \A H \in E \ {G} : Ranked(s, G, H)
          IN Walk(S, Append(ch, W), lost \cup {<<G, cyc \/ (U[G][W] /\ U[W][G])>> : G \in C \ {W}})

(* walkOrphan: a conflict, and the revocations to reissue. *)
RECURSIVE WalkOrphan(_, _, _)
WalkOrphan(S, G, probe) ==
  LET r    == Rec(G)
      rv   == Revokes(StateAt(r.parent), r)
      here == CASE rv /\ probe.ok /\ AlreadyRevoked(probe.s, r) ->
                     [c |-> FALSE, u |-> {}, p |-> probe]
                [] rv /\ probe.ok /\ ProbeApplies(probe.s, r) ->
                     [c |-> FALSE, u |-> {Rep(G)}, p |-> [ok |-> TRUE, s |-> ProbeApply(probe.s, r)]]
                [] rv ->
                     [c |-> TRUE, u |-> {}, p |-> NoProbe]
                [] ~probe.ok ->
                     [c |-> FALSE, u |-> {}, p |-> NoProbe]
                [] ProbeApplies(probe.s, r) ->
                     [c |-> FALSE, u |-> {}, p |-> [ok |-> TRUE, s |-> ProbeApply(probe.s, r)]]
                [] OTHER ->
                     [c |-> TRUE, u |-> {}, p |-> NoProbe]
      kids == {WalkOrphan(S, H, here.p) : H \in ChildGroups(S, G)}
  IN [c |-> here.c \/ \E k \in kids : k.c, u |-> here.u \cup UNION {k.u : k \in kids}]

(* resolve: the chain, naming the copy each next record hangs from, and each
   branch off it walked as an orphan; one the winner's and it each undo, or
   beside a cycle, is a conflict while a revocation of it is still to redo. *)
Resolve(S, a) ==
  LET walk  == Walk(S, <<Copies(S, a)>>, {})
      ch    == walk[1]
      n     == Len(ch)
      ids   == [k \in 1..n |-> IF k = n THEN Rep(ch[k]) ELSE ParentOf(ch[k + 1])]
      final == StateAt(ids[n])
      walks == {LET w == WalkOrphan(S, r[1], [ok |-> TRUE, s |-> final])
                IN [c |-> w.c \/ (r[2] /\ w.u # {}), u |-> w.u] : r \in walk[2]}
  IN [chain     |-> ids,
      onChain   |-> UNION {ch[k] : k \in 1..n},
      head      |-> ids[n],
      state     |-> final,
      alarm     |-> \E w \in walks : w.c,
      unrevoked |-> UNION {w.u : w \in walks}]

Res(v) == res[v]

(* Authority.TrustedState. *)
Trusted(v) == ~Res(v).alarm /\ ~rollback[v]

----------------------------------------------------------------------------

Init ==
  /\ rec = <<>>
  /\ store = [v \in Validators |-> {0}]
  /\ anchor = [v \in Validators |-> 0]
  /\ floor = [v \in Validators |-> 0]
  /\ rollback = [v \in Validators |-> FALSE]
  /\ res = [v \in Validators |-> Resolve({0}, 0)]
  /\ owed = <<>>

Subjects(kind) ==
  CASE kind \in {"AddNode", "RemoveNode"} -> Nodes
    [] kind = "RemoveAdmin"               -> Keys
    [] OTHER                              -> {"-"}

Quorums(kind) == IF kind = "SetQuorum" THEN 1..Cardinality(Holders) ELSE {0}

(* The signer sets an honest quorum makes: none without one of its keys. *)
Minimal(s) == {S \in SUBSET s.admins : Votes(s, S) >= s.quorum /\ \A k \in S : Votes(s, S \ {k}) < s.quorum}

(* Authority.Learn and settle: a record whose parent v holds, refused unless
   authorized there; below the floor, stored under a rollback alarm. *)
Take(v, i) ==
  LET S == store[v] \cup {i}
      R == Resolve(S, anchor[v])
      below == R.state.epoch < floor[v]
  IN /\ store' = [store EXCEPT ![v] = S]
     /\ rollback' = [rollback EXCEPT ![v] = below]
     /\ floor' = [floor EXCEPT ![v] = IF below THEN @ ELSE R.state.epoch]
     /\ res' = [res EXCEPT ![v] = R]

(* A record of r's content is written: a copy takes the content's SigHash
   order and sorts below or above the copies there are; a content new takes
   an order of its own. At most two copies, which a store always keeps. *)
Write(r, by) ==
  /\ Len(rec) < MaxRecords
  /\ LET same  == {j \in Ids : ~Bumps(r.kind) /\ Content(rec[j]) = Content(r)}
         used  == {rec[j].srank : j \in Ids}
     IN /\ same = {} \/ CopiesWritten \/ by = "none"
        /\ Cardinality(same) < 2
        /\ \A j \in same : rec[j].signers # r.signers
        /\ \E sr \in (IF same = {} THEN (1..MaxRecords) \ used ELSE {rec[CHOOSE j \in same : TRUE].srank}),
              hr \in (IF same = {} THEN {1} ELSE {0, 2}) :
             LET full == r @@ [srank |-> sr, hrank |-> hr,
                               key |-> IF Bumps(r.kind) THEN <<Len(rec) + 1>> ELSE Content(r)]
             IN /\ rec' = Append(rec, full)
                /\ owed' = IF by # "none" /\ AuthorTakesIn THEN <<by, Len(rec) + 1>> ELSE <<>>
  /\ UNCHANGED <<store, anchor, floor, rollback, res>>

(* An admin's change on the head its device v holds, signed by just a
   quorum. *)
Change(v) ==
  \E kind \in Kinds :
    LET p == Res(v).head
        s == StateAt(p)
    IN \E subj \in Subjects(kind), q \in Quorums(kind), signers \in Minimal(s) :
         LET r == [parent |-> p, kind |-> kind, subj |-> subj, q |-> q, signers |-> signers]
         IN /\ Valid(s, r)
            /\ Write(r @@ [after |-> Apply(s, r)], v)

(* Another set of admins signing what v holds: a copy. *)
Countersign(v) ==
  /\ CopiesWritten
  /\ \E i \in store[v] \ {0} :
       LET s == StateAt(rec[i].parent)
       IN /\ ~Bumps(rec[i].kind)
          /\ \E signers \in {S \in SUBSET s.admins : Votes(s, S) >= s.quorum} :
               Write([parent |-> rec[i].parent, kind |-> rec[i].kind, subj |-> rec[i].subj, q |-> rec[i].q,
                      signers |-> signers, after |-> rec[i].after], v)

(* The attacker's keys sign a change on any record, authorized or not. *)
Forge ==
  /\ Compromised # {}
  /\ \E p \in {0} \cup Ids, kind \in Kinds :
       LET s == StateAt(p)
       IN \E subj \in Subjects(kind), q \in Quorums(kind), signers \in (SUBSET Compromised) \ {{}} :
            LET r == [parent |-> p, kind |-> kind, subj |-> subj, q |-> q, signers |-> signers]
            IN /\ Applies(s, r)
               /\ Write(r @@ [after |-> Apply(s, r)], "none")

Deliver(v, i) ==
  /\ i \notin store[v]
  /\ rec[i].parent \in store[v]
  /\ Valid(StateAt(rec[i].parent), rec[i])
  /\ Take(v, i)
  /\ UNCHANGED <<rec, anchor>>

(* daemon.compactWhenSettled: every other device's head is past the newest
   checkpoint, or one has compacted to the target or past it. The model reads
   each device as it is; juistd, as last heard. *)
Past(u, cp) == cp \in Res(u).onChain \/ cp \in Ancestors(anchor[u])
Heard(v, newest, target) ==
  \/ \A u \in Validators \ {v} : Past(u, newest)
  \/ \E u \in Validators \ {v} : target \in Ancestors(anchor[u])

(* Authority.Compact: to the checkpoint before the newest on the chain,
   refused under an alarm or with a revocation to redo. *)
Compact(v) ==
  /\ CompactPolicy # "none"
  /\ Trusted(v)
  /\ Res(v).unrevoked = {}
  /\ LET ch  == Res(v).chain
         cps == SelectSeq(SubSeq(ch, 2, Len(ch)), LAMBDA i : rec[i].kind = "Checkpoint")
         a   == cps[Len(cps) - 1]
         S   == UNION {SubIds(store[v], c) : c \in Copies(store[v], a)}
     IN /\ Len(cps) >= 2
        /\ CompactPolicy = "heard" => Heard(v, cps[Len(cps)], a)
        /\ anchor' = [anchor EXCEPT ![v] = a]
        /\ store' = [store EXCEPT ![v] = S]
        /\ res' = [res EXCEPT ![v] = Resolve(S, a)]
  /\ UNCHANGED <<rec, floor, rollback>>

(* The author's device takes its record in before anything else happens. *)
Next ==
  IF owed # <<>>
  THEN Deliver(owed[1], owed[2]) /\ owed' = <<>>
  ELSE \/ \E v \in Validators : Change(v) \/ Countersign(v)
       \/ Forge
       \/ (\E v \in Validators, i \in Ids : Deliver(v, i)) /\ UNCHANGED owed
       \/ (\E v \in Validators : Compact(v)) /\ UNCHANGED owed

Spec == Init /\ [][Next]_vars

(* Keys alike are interchangeable, and so are the validators. *)
Symmetry ==
  Permutations((Keys \ PairedKeys) \ Compromised) \cup Permutations(PairedKeys \ Compromised)
    \cup Permutations(Validators)

----------------------------------------------------------------------------
(* The properties. *)

(* Every record on a chain has its quorum at its parent. *)
QuorumOnChain ==
  \A v \in Validators : \A i \in Res(v).onChain \ {0} : Authorized(StateAt(rec[i].parent), rec[i])

(* No trusted state is below the epoch floor. *)
FloorHolds == \A v \in Validators : Trusted(v) => Res(v).state.epoch >= floor[v]

(* The branches off v's chain, each with the chain's record beside it. *)
Beside(v) ==
  LET R  == Res(v)
      gs == [k \in 1..Len(R.chain) |-> Copies(store[v], R.chain[k])]
  IN UNION {{<<O, gs[k + 1]>> : O \in ChildGroups(store[v], gs[k]) \ {gs[k + 1]}} : k \in 1..(Len(gs) - 1)}

(* On a trusted chain, a revocation beside it lost to no branch with a record
   that keeps its quorum only by keys the revocation's branch removes and
   the winning branch keeps, its copies' signatures united. Stated apart
   from Undone, which the code's rule mirrors. *)
RemovedKeyUndoesNoRevocation ==
  \A v \in Validators :
    Trusted(v) => \A b \in Beside(v) :
      Revokes(StateAt(ParentOf(b[1])), Rec(b[1])) =>
        LET gone == BranchRemoves(store[v], b[1]) \ BranchRemoves(store[v], b[2])
        IN \A H \in SubG(store[v], b[2]) :
             Votes(StateAt(ParentOf(H)), SignersOf(H) \ gone) >= StateAt(ParentOf(H)).quorum

(* A raised quorum beside a trusted chain lost to no branch the attacker's
   keys signed with fewer votes than it: those the raise stripped (M33, "A
   raise undone by a ground revocation"). *)
RaiseHoldsAgainstStrippedKeys ==
  \A v \in Validators :
    Trusted(v) => \A b \in Beside(v) :
      (Rec(b[1]).kind = "SetQuorum" /\ Revokes(StateAt(ParentOf(b[1])), Rec(b[1]))) =>
        SignersOf(b[2]) \cap Compromised = {} \/ Votes(StateAt(ParentOf(b[2])), SignersOf(b[2])) >= Rec(b[1]).q

(* Nothing left that a validator could take in. *)
Quiescent == \A v \in Validators : \A i \in Ids : i \notin store[v] => rec[i].parent \notin store[v]

(* Validators that trust their state hold one head, any copy of it. *)
Agreement ==
  Quiescent => \A u, v \in Validators : Trusted(u) /\ Trusted(v) => KeyOf(Res(u).head) = KeyOf(Res(v).head)

(* Validators that trust their state hold one head, and a fork alarm is
   raised everywhere or nowhere. *)
Convergence ==
  Quiescent => /\ Agreement
               /\ \A u, v \in Validators : Res(u).alarm = Res(v).alarm

=============================================================================
