package consensus

import (
	"runtime"
	"sync"
	"testing"
)

func TestOpenSSL_VerifySig_ParallelDeterministic(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x42
	digest[31] = 0xA5

	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	ok, err := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if err != nil {
		t.Fatalf("verifySig warmup err: %v", err)
	}
	if !ok {
		t.Fatalf("verifySig warmup=false")
	}

	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 4 {
		workers = 4
	}
	const loopsPerWorker = 200

	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for workerIdx := 0; workerIdx < workers; workerIdx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < loopsPerWorker; iter++ {
				okValid, errValid := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
				if errValid != nil {
					errCh <- errValid
					return
				}
				if !okValid {
					errCh <- txerr(TX_ERR_PARSE, "parallel verify returned false for valid signature")
					return
				}

				invalidDigest := digest
				invalidDigest[0] ^= 0x01
				okInvalid, errInvalid := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, invalidDigest)
				if errInvalid != nil {
					errCh <- errInvalid
					return
				}
				if okInvalid {
					errCh <- txerr(TX_ERR_PARSE, "parallel verify returned true for invalid digest")
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for gotErr := range errCh {
		if gotErr != nil {
			t.Fatalf("parallel verify failed: %v", gotErr)
		}
	}
}
