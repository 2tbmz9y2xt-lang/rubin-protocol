import RubinFormal.Conformance.CVVaultPolicyVectors

namespace RubinFormal.Conformance

def strictlySortedUnique (xs : List String) : Bool :=
  let rec go : List String → Bool
    | [] => true
    | [_] => true
    | x :: y :: rest =>
        if x < y then go (y :: rest) else false
  go xs

def vaultPolicyEval (v : CVVaultPolicyVector) : (Bool × Option String) :=
  let sentinelOk :=
    v.sentinelSuiteId == 0 &&
    v.sentinelPubkeyLen == 0 &&
    v.sentinelSigLen == 0 &&
    (!v.sentinelVerifyCalled)
  let whitelistOk := strictlySortedUnique v.whitelist
  let checks : List (String × (Bool × String)) := [
    ("multi_vault", (v.vaultInputCount <= 1, "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN")),
    ("owner_auth", (v.hasOwnerAuth, "TX_ERR_VAULT_OWNER_AUTH_REQUIRED")),
    ("fee_sponsor", ((v.nonVaultLockIds.all (fun x => x == v.ownerLockId)), "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN")),
    ("witness_slots", (v.slots == v.keyCount, "TX_ERR_PARSE")),
    ("sentinel", (sentinelOk, "TX_ERR_PARSE")),
    ("sig_threshold", (v.sigThresholdOk, "TX_ERR_SIG_INVALID")),
    ("whitelist", (whitelistOk, "TX_ERR_VAULT_WHITELIST_NOT_CANONICAL")),
    ("value", (v.sumOut >= v.sumInVault, "TX_ERR_VALUE_CONSERVATION"))
  ]

  let order :=
    match v.validationOrder with
    | none => ["multi_vault","owner_auth","fee_sponsor","witness_slots","sentinel","sig_threshold","whitelist","value"]
    | some xs => xs

  let err : Option String :=
    order.foldl
      (fun acc rule =>
        match acc with
        | some e => some e
        | none =>
            match checks.find? (fun (k, _) => k == rule) with
            | none => some "TX_ERR_PARSE"
            | some (_, (ok, code)) =>
                if ok then none else some code
      )
      none
  let ok := err.isNone
  (ok, err)

def vaultPolicyVectorPass (v : CVVaultPolicyVector) : Bool :=
  let (ok, err) := vaultPolicyEval v
  if v.expectOk then
    ok
  else
    (!ok) && (err == v.expectErr)

def cvVaultPolicyVectorsPass : Bool :=
  cvVaultPolicyVectors.all vaultPolicyVectorPass

theorem cv_vault_policy_vectors_pass : cvVaultPolicyVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
