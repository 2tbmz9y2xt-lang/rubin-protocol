import Std
import RubinFormal.Conformance.CVNativeRotationDescriptorVectors

namespace RubinFormal.Conformance

def registeredNativeSuites : List Nat := [1, 2]

def isRegistered (suiteId : Nat) : Bool :=
  registeredNativeSuites.contains suiteId

def validateDesc (d : RotationDesc) : Bool :=
  (d.name.trim != "") &&
  (d.oldSuiteId != d.newSuiteId) &&
  isRegistered d.oldSuiteId &&
  isRegistered d.newSuiteId &&
  (d.createHeight < d.spendHeight) &&
  (d.sunsetHeight == 0 || d.sunsetHeight > d.spendHeight)

def intervalsOverlap (a b : RotationDesc) : Bool :=
  (a.createHeight < b.spendHeight) && (b.createHeight < a.spendHeight)

def noOverlaps : List RotationDesc → Bool
  | [] => true
  | x :: xs =>
      xs.all (fun y => !(intervalsOverlap x y)) && noOverlaps xs

def validateRotationSet (ds : List RotationDesc) : Bool :=
  ds.all validateDesc && noOverlaps ds

def checkNativeRotationDescriptorVector (v : CVNativeRotationDescriptorVector) : Bool :=
  let gotOk := validateRotationSet v.descriptors
  gotOk == v.expectOk

def allCVNativeRotationDescriptor : Bool :=
  cvNativeRotationDescriptorVectors.all checkNativeRotationDescriptorVector

theorem cv_native_rotation_descriptor_vectors_pass : allCVNativeRotationDescriptor = true := by
  native_decide

end RubinFormal.Conformance

