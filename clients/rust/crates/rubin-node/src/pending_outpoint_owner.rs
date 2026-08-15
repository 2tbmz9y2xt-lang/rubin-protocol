use crate::ChainState;
use rubin_consensus::constants::MAX_TX_INPUTS;
use rubin_consensus::Outpoint;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PendingOutpointTip {
    pub(crate) has_tip: bool,
    pub(crate) height: u64,
    pub(crate) hash: [u8; 32],
}
impl PendingOutpointTip {
    pub(crate) fn from_chain_state(state: &ChainState) -> Self {
        Self {
            has_tip: state.has_tip,
            height: state.height,
            hash: state.tip_hash,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingOutpointAdmissionContext {
    pub(crate) tip: PendingOutpointTip,
    pub(crate) generation: u64,
}
#[derive(Clone)]
pub(crate) struct PendingOutpointToken {
    owner: Weak<Mutex<PendingOutpointOwner>>,
    sequence: u64,
}
impl std::fmt::Debug for PendingOutpointToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PendingOutpointToken")
            .field(&self.sequence)
            .finish()
    }
}
impl PartialEq for PendingOutpointToken {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence && Weak::ptr_eq(&self.owner, &other.owner)
    }
}
impl Eq for PendingOutpointToken {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingOutpointErrorKind {
    Conflict,
    Unavailable,
    Internal,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingOutpointError {
    pub(crate) kind: PendingOutpointErrorKind,
    pub(crate) message: String,
    pub(crate) existing_txid: Option<[u8; 32]>,
}
impl PendingOutpointError {
    fn conflict(txid: [u8; 32]) -> Self {
        Self {
            kind: PendingOutpointErrorKind::Conflict,
            message: format!("mempool double-spend conflict with {}", hex::encode(txid)),
            existing_txid: Some(txid),
        }
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: PendingOutpointErrorKind::Unavailable,
            message: message.into(),
            existing_txid: None,
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: PendingOutpointErrorKind::Internal,
            message: message.into(),
            existing_txid: None,
        }
    }
}
#[derive(Clone)]
pub(crate) struct PendingOutpointOwnerHandle {
    inner: Arc<Mutex<PendingOutpointOwner>>,
}
impl std::fmt::Debug for PendingOutpointOwnerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingOutpointOwnerHandle")
            .finish_non_exhaustive()
    }
}
impl PendingOutpointOwnerHandle {
    pub(crate) fn new(tip: PendingOutpointTip) -> Self {
        Self::new_with_context(PendingOutpointAdmissionContext { tip, generation: 0 })
    }
    pub(crate) fn new_with_context(context: PendingOutpointAdmissionContext) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PendingOutpointOwner {
                by_outpoint: HashMap::new(),
                by_token: HashMap::new(),
                token_high_water: 0,
                generation: context.generation,
                transition: false,
                unavailable: false,
                stable_tip: context.tip,
            })),
        }
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    pub(crate) fn admission_context(
        &self,
    ) -> Result<PendingOutpointAdmissionContext, PendingOutpointError> {
        self.lock()?.admission_context()
    }
    pub(crate) fn reserve(
        &self,
        context: PendingOutpointAdmissionContext,
        txid: [u8; 32],
        inputs: Vec<Outpoint>,
    ) -> Result<PendingOutpointToken, PendingOutpointError> {
        validate_request(txid, &inputs)?;
        self.lock()?.reserve(self, context, txid, inputs)
    }
    pub(crate) fn finalize(
        &self,
        token: &PendingOutpointToken,
    ) -> Result<(), PendingOutpointError> {
        self.lock()?.finalize(self, token)
    }
    pub(crate) fn release(&self, token: &PendingOutpointToken) -> Result<(), PendingOutpointError> {
        self.lock()?.release(self, token)
    }
    pub(crate) fn txid_for_outpoint(
        &self,
        outpoint: &Outpoint,
    ) -> Result<Option<[u8; 32]>, PendingOutpointError> {
        Ok(self.lock()?.by_outpoint.get(outpoint).map(|row| row.txid))
    }
    pub(crate) fn begin_transition(&self) -> Result<(), PendingOutpointError> {
        self.lock()?.begin_transition()
    }
    pub(crate) fn commit_stable_tip(
        &self,
        tip: PendingOutpointTip,
    ) -> Result<(), PendingOutpointError> {
        self.lock()?.commit_stable_tip(tip)
    }
    pub(crate) fn reopen_old_tip(&self) -> Result<(), PendingOutpointError> {
        self.lock()?.reopen_old_tip()
    }
    pub(crate) fn latch_unavailable(&self) {
        if let Ok(mut owner) = self.lock() {
            owner.unavailable = true;
            owner.transition = false;
        }
    }
    pub(crate) fn lock(
        &self,
    ) -> Result<MutexGuard<'_, PendingOutpointOwner>, PendingOutpointError> {
        self.inner.lock().map_err(|_| {
            PendingOutpointError::unavailable("pending-outpoint owner lock unavailable")
        })
    }
    fn owns(&self, token: &PendingOutpointToken) -> bool {
        token.sequence != 0 && Weak::ptr_eq(&token.owner, &Arc::downgrade(&self.inner))
    }
    fn token(&self, sequence: u64) -> PendingOutpointToken {
        PendingOutpointToken {
            owner: Arc::downgrade(&self.inner),
            sequence,
        }
    }
    #[cfg(test)]
    pub(crate) fn test_row_count(&self) -> Result<usize, PendingOutpointError> {
        Ok(self.lock()?.by_outpoint.len())
    }
    #[cfg(test)]
    pub(crate) fn test_high_water(&self) -> u64 {
        self.lock().expect("test owner lock").token_high_water
    }
    #[cfg(test)]
    pub(crate) fn test_set_high_water(&self, high_water: u64) {
        self.lock().expect("test owner lock").token_high_water = high_water;
    }
}
pub(crate) struct PendingOutpointOwner {
    by_outpoint: HashMap<Outpoint, PendingOutpointRow>,
    by_token: HashMap<u64, PendingOutpointClaim>,
    token_high_water: u64,
    generation: u64,
    transition: bool,
    unavailable: bool,
    stable_tip: PendingOutpointTip,
}
struct PendingOutpointRow {
    sequence: u64,
    txid: [u8; 32],
}
struct PendingOutpointClaim {
    txid: [u8; 32],
    inputs: Vec<Outpoint>,
    generation: u64,
    finalized: bool,
}
impl PendingOutpointOwner {
    fn admission_context(&self) -> Result<PendingOutpointAdmissionContext, PendingOutpointError> {
        if self.transition || self.unavailable || self.generation == u64::MAX {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint owner admission context unavailable",
            ));
        }
        Ok(PendingOutpointAdmissionContext {
            tip: self.stable_tip,
            generation: self.generation,
        })
    }
    fn reserve(
        &mut self,
        handle: &PendingOutpointOwnerHandle,
        context: PendingOutpointAdmissionContext,
        txid: [u8; 32],
        inputs: Vec<Outpoint>,
    ) -> Result<PendingOutpointToken, PendingOutpointError> {
        self.check_available(context)?;
        let sequence = self.token_high_water.checked_add(1).ok_or_else(|| {
            PendingOutpointError::unavailable("pending-outpoint token sequence exhausted")
        })?;
        self.first_conflict(&inputs)?;
        self.by_token.try_reserve(1).map_err(|_| {
            PendingOutpointError::unavailable("pending-outpoint token capacity unavailable")
        })?;
        self.by_outpoint.try_reserve(inputs.len()).map_err(|_| {
            PendingOutpointError::unavailable("pending-outpoint row capacity unavailable")
        })?;
        self.token_high_water = sequence;
        self.by_token.insert(
            sequence,
            PendingOutpointClaim {
                txid,
                inputs,
                generation: self.generation,
                finalized: false,
            },
        );
        let claim = self.by_token.get(&sequence).ok_or_else(|| {
            PendingOutpointError::internal("pending-outpoint claim publication failed")
        })?;
        for outpoint in &claim.inputs {
            self.by_outpoint
                .insert(outpoint.clone(), PendingOutpointRow { sequence, txid });
        }
        Ok(handle.token(sequence))
    }
    fn finalize(
        &mut self,
        handle: &PendingOutpointOwnerHandle,
        token: &PendingOutpointToken,
    ) -> Result<(), PendingOutpointError> {
        self.check_candidate(handle, token)?;
        let claim = self
            .by_token
            .get_mut(&token.sequence)
            .ok_or_else(|| PendingOutpointError::internal("pending-outpoint claim is not live"))?;
        claim.finalized = true;
        Ok(())
    }
    fn release(
        &mut self,
        handle: &PendingOutpointOwnerHandle,
        token: &PendingOutpointToken,
    ) -> Result<(), PendingOutpointError> {
        let Some(claim) = self.claim(handle, token)? else {
            return if self
                .by_outpoint
                .values()
                .any(|row| row.sequence == token.sequence)
            {
                Err(PendingOutpointError::internal(
                    "pending-outpoint claim is missing with live row",
                ))
            } else {
                Ok(())
            };
        };
        for outpoint in &claim.inputs {
            let Some(row) = self.by_outpoint.get(outpoint) else {
                return Err(PendingOutpointError::internal(
                    "pending-outpoint row is missing",
                ));
            };
            if row.sequence != token.sequence || row.txid != claim.txid {
                return Err(PendingOutpointError::internal(
                    "pending-outpoint row mismatch",
                ));
            }
        }
        self.drop_claim(token.sequence);
        Ok(())
    }
    pub(crate) fn validate_standard_entry(
        &self,
        handle: &PendingOutpointOwnerHandle,
        txid: [u8; 32],
        inputs: &[Outpoint],
        token: Option<&PendingOutpointToken>,
        finalized: bool,
    ) -> Result<(), PendingOutpointError> {
        if inputs.is_empty() {
            return if token.is_none() {
                Ok(())
            } else {
                Err(PendingOutpointError::internal(
                    "pending-outpoint token on inputless entry",
                ))
            };
        }
        let token = token
            .ok_or_else(|| PendingOutpointError::internal("missing pending-outpoint token"))?;
        let claim = self
            .claim(handle, token)?
            .ok_or_else(|| PendingOutpointError::internal("pending-outpoint claim is not live"))?;
        if claim.txid != txid || claim.finalized != finalized || claim.inputs != inputs {
            return Err(PendingOutpointError::internal(
                "pending-outpoint claim mismatch",
            ));
        }
        for outpoint in inputs {
            let Some(row) = self.by_outpoint.get(outpoint) else {
                return Err(PendingOutpointError::internal(
                    "pending-outpoint row is missing",
                ));
            };
            if row.sequence != token.sequence || row.txid != txid {
                return Err(PendingOutpointError::internal(
                    "pending-outpoint row mismatch",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn check_candidate(
        &self,
        handle: &PendingOutpointOwnerHandle,
        token: &PendingOutpointToken,
    ) -> Result<(), PendingOutpointError> {
        if self.transition || self.unavailable {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint owner transition in progress",
            ));
        }
        let claim = self.claim(handle, token)?.ok_or_else(|| {
            PendingOutpointError::unavailable("pending-outpoint token is no longer live")
        })?;
        if claim.generation != self.generation {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint token belongs to an older generation",
            ));
        }
        Ok(())
    }
    fn begin_transition(&mut self) -> Result<(), PendingOutpointError> {
        if self.transition || self.unavailable {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint owner transition already active",
            ));
        }
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            PendingOutpointError::unavailable("pending-outpoint generation exhausted")
        })?;
        self.transition = true;
        Ok(())
    }
    fn commit_stable_tip(&mut self, tip: PendingOutpointTip) -> Result<(), PendingOutpointError> {
        if !self.transition || self.unavailable {
            return Err(PendingOutpointError::internal(
                "pending-outpoint stable tip commit without active transition",
            ));
        }
        self.stable_tip = tip;
        self.transition = false;
        Ok(())
    }
    fn reopen_old_tip(&mut self) -> Result<(), PendingOutpointError> {
        if !self.transition || self.unavailable {
            return Err(PendingOutpointError::internal(
                "pending-outpoint transition abort without active transition",
            ));
        }
        self.transition = false;
        Ok(())
    }
    pub(crate) fn check_available(
        &self,
        context: PendingOutpointAdmissionContext,
    ) -> Result<(), PendingOutpointError> {
        if self.transition || self.unavailable {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint owner transition in progress",
            ));
        }
        if context.tip != self.stable_tip {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint expected tip mismatch",
            ));
        }
        if context.generation != self.generation {
            return Err(PendingOutpointError::unavailable(
                "pending-outpoint expected generation mismatch",
            ));
        }
        Ok(())
    }
    fn first_conflict(&self, inputs: &[Outpoint]) -> Result<(), PendingOutpointError> {
        for outpoint in inputs {
            if let Some(row) = self.by_outpoint.get(outpoint) {
                return Err(PendingOutpointError::conflict(row.txid));
            }
        }
        Ok(())
    }
    fn claim<'a>(
        &'a self,
        handle: &PendingOutpointOwnerHandle,
        token: &PendingOutpointToken,
    ) -> Result<Option<&'a PendingOutpointClaim>, PendingOutpointError> {
        if !handle.owns(token) {
            return Err(PendingOutpointError::internal(
                "zero or foreign pending-outpoint token",
            ));
        }
        if token.sequence > self.token_high_water {
            return Err(PendingOutpointError::internal(
                "pending-outpoint token sequence above high-water",
            ));
        }
        Ok(self.by_token.get(&token.sequence))
    }
    pub(crate) fn drop_claim(&mut self, sequence: u64) {
        let Some(claim) = self.by_token.remove(&sequence) else {
            return;
        };
        for outpoint in claim.inputs {
            if self
                .by_outpoint
                .get(&outpoint)
                .is_some_and(|row| row.sequence == sequence)
            {
                self.by_outpoint.remove(&outpoint);
            }
        }
    }
    pub(crate) fn finalize_after_validation(&mut self, token: &PendingOutpointToken) {
        if let Some(claim) = self.by_token.get_mut(&token.sequence) {
            claim.finalized = true;
        }
    }
    pub(crate) fn drop_after_validation(&mut self, token: &PendingOutpointToken) {
        self.drop_claim(token.sequence);
    }
}
fn validate_request(txid: [u8; 32], inputs: &[Outpoint]) -> Result<(), PendingOutpointError> {
    if txid == [0; 32] {
        return Err(PendingOutpointError::internal("zero pending-outpoint txid"));
    }
    if inputs.is_empty() || inputs.len() > MAX_TX_INPUTS as usize {
        return Err(PendingOutpointError::internal(
            "invalid pending-outpoint input count",
        ));
    }
    let mut seen = HashSet::new();
    seen.try_reserve(inputs.len()).map_err(|_| {
        PendingOutpointError::unavailable("pending-outpoint input capacity unavailable")
    })?;
    for outpoint in inputs {
        if !seen.insert(outpoint.clone()) {
            return Err(PendingOutpointError::internal(
                "duplicate pending-outpoint input",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn outpoint(tag: u8) -> Outpoint {
        Outpoint {
            txid: [tag; 32],
            vout: u32::from(tag),
        }
    }
    fn new_owner() -> PendingOutpointOwnerHandle {
        PendingOutpointOwnerHandle::new(PendingOutpointTip::default())
    }
    fn state(owner: &PendingOutpointOwnerHandle) -> (u64, usize) {
        (
            owner.test_high_water(),
            owner.test_row_count().expect("rows"),
        )
    }
    #[test]
    fn reservation_conflict_is_ordered_and_exact_release_is_idempotent() {
        let owner = new_owner();
        let context = owner.admission_context().expect("context");
        let first = owner
            .reserve(context, [1; 32], vec![outpoint(1)])
            .expect("first reservation");
        let second = owner
            .reserve(context, [2; 32], vec![outpoint(2)])
            .expect("second reservation");
        let high_water = owner.test_high_water();
        let error = owner
            .reserve(context, [3; 32], vec![outpoint(2), outpoint(1)])
            .expect_err("first requested conflict wins in canonical input order");
        assert_eq!(error.kind, PendingOutpointErrorKind::Conflict);
        assert_eq!(error.existing_txid, Some([2; 32]));
        assert_eq!(owner.test_high_water(), high_water);
        owner.finalize(&first).expect("finalize first");
        owner.finalize(&second).expect("finalize second");
        {
            let mut guard = owner.lock().expect("owner lock");
            guard.by_outpoint.insert(
                outpoint(1),
                PendingOutpointRow {
                    sequence: first.sequence + 1,
                    txid: [4; 32],
                },
            );
            guard.drop_claim(first.sequence);
        }
        assert_eq!(
            owner
                .txid_for_outpoint(&outpoint(1))
                .expect("newer row lookup"),
            Some([4; 32])
        );
        owner.release(&first).expect("absent exact retry");
        owner.release(&second).expect("release second");
        owner.test_set_high_water(u64::MAX - 1);
        let max = owner
            .reserve(context, [5; 32], vec![outpoint(5)])
            .expect("max token");
        owner.finalize(&max).expect("finalize max token");
        owner.release(&max).expect("release max token");
        let before = state(&owner);
        let exhausted = owner
            .reserve(context, [6; 32], vec![outpoint(6)])
            .expect_err("exhausted");
        assert_eq!(
            exhausted.message,
            "pending-outpoint token sequence exhausted"
        );
        assert_eq!(state(&owner), before);
    }
    #[test]
    fn foreign_future_and_stale_tokens_fail_closed_but_exact_release_survives_generation() {
        let owner = new_owner();
        let context = owner.admission_context().expect("context");
        let token = owner
            .reserve(context, [3; 32], vec![outpoint(3)])
            .expect("reservation");
        let before_zero = state(&owner);
        let zero = owner.release(&owner.token(0)).expect_err("zero token");
        assert_eq!(zero.kind, PendingOutpointErrorKind::Internal);
        assert_eq!(zero.message, "zero or foreign pending-outpoint token");
        assert_eq!(state(&owner), before_zero);
        let other = new_owner();
        let foreign = other
            .reserve(
                other.admission_context().expect("other context"),
                [4; 32],
                vec![outpoint(4)],
            )
            .expect("foreign reservation");
        assert_eq!(
            owner.release(&foreign).expect_err("foreign token").kind,
            PendingOutpointErrorKind::Internal
        );
        let future = owner.token(owner.test_high_water().saturating_add(1));
        assert_eq!(
            owner.release(&future).expect_err("future token").kind,
            PendingOutpointErrorKind::Internal
        );
        owner.begin_transition().expect("begin transition");
        assert_eq!(
            owner
                .admission_context()
                .expect_err("context fenced during transition")
                .kind,
            PendingOutpointErrorKind::Unavailable
        );
        assert_eq!(
            owner.finalize(&token).expect_err("stale finalize").kind,
            PendingOutpointErrorKind::Unavailable
        );
        owner.reopen_old_tip().expect("reopen old stable tip");
        let before_stale = state(&owner);
        for error in [
            owner.finalize(&token).expect_err("old finalize"),
            owner
                .lock()
                .expect("owner lock")
                .check_candidate(&owner, &token)
                .expect_err("old candidate"),
        ] {
            assert_eq!(error.kind, PendingOutpointErrorKind::Unavailable);
            assert_eq!(
                error.message,
                "pending-outpoint token belongs to an older generation"
            );
        }
        assert_eq!(state(&owner), before_stale);
        owner
            .release(&token)
            .expect("generation independent release");
        let partial = owner
            .reserve(
                owner.admission_context().expect("reopened context"),
                [5; 32],
                vec![outpoint(5)],
            )
            .expect("partial reservation");
        let mut guard = owner.lock().expect("owner lock");
        guard.by_outpoint.remove(&outpoint(5));
        drop(guard);
        let before_partial = state(&owner);
        let partial_error = owner.release(&partial).expect_err("partial token");
        assert_eq!(partial_error.kind, PendingOutpointErrorKind::Internal);
        assert_eq!(partial_error.message, "pending-outpoint row is missing");
        assert_eq!(state(&owner), before_partial);
        let mut guard = owner.lock().expect("owner lock");
        assert!(guard.by_token.contains_key(&partial.sequence));
        guard.by_outpoint.insert(
            outpoint(5),
            PendingOutpointRow {
                sequence: partial.sequence,
                txid: [5; 32],
            },
        );
        guard.by_token.remove(&partial.sequence);
        drop(guard);
        let before_inverse = state(&owner);
        let inverse = owner.release(&partial).expect_err("inverse partial token");
        assert_eq!(inverse.kind, PendingOutpointErrorKind::Internal);
        assert_eq!(
            inverse.message,
            "pending-outpoint claim is missing with live row"
        );
        assert_eq!(
            owner.txid_for_outpoint(&outpoint(5)).expect("row lookup"),
            Some([5; 32])
        );
        assert_eq!(state(&owner), before_inverse);
        let mut guard = owner.lock().expect("owner lock");
        guard.by_outpoint.remove(&outpoint(5));
        drop(guard);
        owner.release(&partial).expect("absent cleanup");
    }
    #[test]
    #[rustfmt::skip]
    fn defensive_error_kinds_and_messages_are_exact() {
        macro_rules! err { ($e:expr,$k:ident,$m:literal) => {{ let e=$e.expect_err($m); assert_eq!((e.kind,e.message.as_str()),(PendingOutpointErrorKind::$k,$m)); }} }
        let snap=|o:&PendingOutpointOwnerHandle,seq:u64,op:&Outpoint| { let g=o.lock().unwrap(); (g.token_high_water,g.generation,g.transition,g.unavailable,g.stable_tip,g.by_token.get(&seq).map(|c|(c.txid,c.inputs.clone(),c.generation,c.finalized)),g.by_outpoint.get(op).map(|r|(r.sequence,r.txid))) };
        let owner=new_owner(); let context=owner.admission_context().unwrap();
        assert_eq!(format!("{:?}",owner),"PendingOutpointOwnerHandle { .. }");
        let before=state(&owner); for (txid,inputs,message) in [([0;32],vec![outpoint(1)],"zero pending-outpoint txid"),([1;32],vec![],"invalid pending-outpoint input count"),([1;32],vec![outpoint(1),outpoint(1)],"duplicate pending-outpoint input")] { let e=owner.reserve(context,txid,inputs).unwrap_err(); assert_eq!((e.kind,e.message.as_str()),(PendingOutpointErrorKind::Internal,message)); } assert_eq!(state(&owner),before);
        let token=owner.reserve(context,[2;32],vec![outpoint(2)]).unwrap(); assert_eq!(format!("{token:?}"),"PendingOutpointToken(1)");
        { let guard=owner.lock().unwrap(); err!(guard.validate_standard_entry(&owner,[2;32],&[],Some(&token),false),Internal,"pending-outpoint token on inputless entry"); err!(guard.validate_standard_entry(&owner,[3;32],&[outpoint(2)],Some(&token),false),Internal,"pending-outpoint claim mismatch"); }
        owner.finalize(&token).unwrap(); { let guard=owner.lock().unwrap(); err!(guard.validate_standard_entry(&owner,[2;32],&[outpoint(2)],Some(&token),false),Internal,"pending-outpoint claim mismatch"); }
        { owner.lock().unwrap().by_outpoint.remove(&outpoint(2)); let guard=owner.lock().unwrap(); err!(guard.validate_standard_entry(&owner,[2;32],&[outpoint(2)],Some(&token),true),Internal,"pending-outpoint row is missing"); }
        { owner.lock().unwrap().by_outpoint.insert(outpoint(2),PendingOutpointRow{sequence:2,txid:[2;32]}); let guard=owner.lock().unwrap(); err!(guard.validate_standard_entry(&owner,[2;32],&[outpoint(2)],Some(&token),true),Internal,"pending-outpoint row mismatch"); }
        let before=snap(&owner,token.sequence,&outpoint(2)); err!(owner.release(&token),Internal,"pending-outpoint row mismatch"); assert_eq!(snap(&owner,token.sequence,&outpoint(2)),before); owner.lock().unwrap().by_outpoint.insert(outpoint(2),PendingOutpointRow{sequence:token.sequence,txid:[2;32]}); owner.release(&token).unwrap();
        let before=snap(&owner,token.sequence,&outpoint(2)); err!(owner.finalize(&token),Unavailable,"pending-outpoint token is no longer live"); owner.lock().unwrap().drop_claim(u64::MAX); assert_eq!(snap(&owner,token.sequence,&outpoint(2)),before);
        let before=snap(&owner,token.sequence,&outpoint(2)); err!(owner.commit_stable_tip(context.tip),Internal,"pending-outpoint stable tip commit without active transition"); err!(owner.reopen_old_tip(),Internal,"pending-outpoint transition abort without active transition"); assert_eq!(snap(&owner,token.sequence,&outpoint(2)),before);
        owner.begin_transition().unwrap(); let before=snap(&owner,token.sequence,&outpoint(2)); err!(owner.begin_transition(),Unavailable,"pending-outpoint owner transition already active");
        { let guard=owner.lock().unwrap(); err!(guard.check_available(context),Unavailable,"pending-outpoint owner transition in progress"); } assert_eq!(snap(&owner,token.sequence,&outpoint(2)),before);
        owner.reopen_old_tip().unwrap(); let wrong=PendingOutpointAdmissionContext{tip:PendingOutpointTip{hash:[9;32],..context.tip},..context};
        { let guard=owner.lock().unwrap(); err!(guard.check_available(wrong),Unavailable,"pending-outpoint expected tip mismatch"); }
        owner.lock().unwrap().generation=u64::MAX; let before=snap(&owner,token.sequence,&outpoint(2)); err!(owner.begin_transition(),Unavailable,"pending-outpoint generation exhausted"); assert_eq!(snap(&owner,token.sequence,&outpoint(2)),before);
        let poisoned=new_owner(); let clone=poisoned.clone(); let _=std::thread::spawn(move||{let _guard=clone.inner.lock().unwrap(); panic!("poison");}).join();
        err!(poisoned.admission_context(),Unavailable,"pending-outpoint owner lock unavailable");
    }
}
