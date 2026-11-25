---------------------------- MODULE PairKeyTrace ----------------------------
(* PairKey, each step named, and the message a delivery took, for
   internal/pairkey's TestTheCodeFollowsThePairKeyModel to replay. *)
EXTENDS PairKey

VARIABLE took

NoMsg == [from |-> "none"]

DoTakeL == \E m \in net : TakeL(m) /\ took' = m
DoTakeF == \E m \in net : TakeF(m) /\ took' = m
DoSendL == SendL /\ took' = NoMsg
DoSendF == SendF /\ took' = NoMsg
DoAdvance == Advance /\ took' = NoMsg
DoProbe == Probe /\ took' = NoMsg
DoBump == Bump /\ took' = NoMsg
DoResetF == ResetF /\ took' = NoMsg
DoResetL == ResetL /\ took' = NoMsg
DoAnnounceToL == AnnounceToL /\ took' = NoMsg
DoAnnounceToF == AnnounceToF /\ took' = NoMsg
DoKeepF == KeepF /\ took' = NoMsg
DoRestoreF == RestoreF /\ took' = NoMsg

TraceSpec == Init /\ took = NoMsg /\
  [][DoTakeL \/ DoTakeF \/ DoSendL \/ DoSendF \/ DoAdvance \/ DoProbe \/ DoBump \/ DoResetF \/ DoResetL
     \/ DoAnnounceToL \/ DoAnnounceToF \/ DoKeepF \/ DoRestoreF]_<<vars, took>>

=============================================================================
