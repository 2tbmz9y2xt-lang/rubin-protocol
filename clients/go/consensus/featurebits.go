package consensus

import "fmt"

type FeatureBitState string

const (
	FEATUREBIT_DEFINED   FeatureBitState = "DEFINED"
	FEATUREBIT_STARTED   FeatureBitState = "STARTED"
	FEATUREBIT_LOCKED_IN FeatureBitState = "LOCKED_IN"
	FEATUREBIT_ACTIVE    FeatureBitState = "ACTIVE"
	FEATUREBIT_FAILED    FeatureBitState = "FAILED"
)

type FeatureBitDeployment struct {
	Name          string
	Bit           uint8
	StartHeight   uint64
	TimeoutHeight uint64
}

type FeatureBitEval struct {
	State               FeatureBitState
	BoundaryHeight      uint64
	PrevWindowSignalCnt uint32
	SignalWindow        uint64
	SignalThreshold     uint32
}

func (d FeatureBitDeployment) Validate() error {
	if d.Bit > 31 {
		return fmt.Errorf("featurebits: bit out of range: %d", d.Bit)
	}
	if d.Name == "" {
		return fmt.Errorf("featurebits: name required")
	}
	if d.TimeoutHeight < d.StartHeight {
		return fmt.Errorf("featurebits: timeout_height < start_height")
	}
	return nil
}

func evalFeatureBitsNextState(
	prev FeatureBitState,
	boundaryHeight uint64,
	prevWindowSignalCount uint32,
	d FeatureBitDeployment,
) FeatureBitState {
	switch prev {
	case FEATUREBIT_DEFINED:
		if boundaryHeight >= d.StartHeight {
			return FEATUREBIT_STARTED
		}
		return FEATUREBIT_DEFINED
	case FEATUREBIT_STARTED:
		if prevWindowSignalCount >= SIGNAL_THRESHOLD {
			return FEATUREBIT_LOCKED_IN
		}
		if boundaryHeight >= d.TimeoutHeight {
			return FEATUREBIT_FAILED
		}
		return FEATUREBIT_STARTED
	case FEATUREBIT_LOCKED_IN:
		return FEATUREBIT_ACTIVE
	case FEATUREBIT_ACTIVE:
		return FEATUREBIT_ACTIVE
	case FEATUREBIT_FAILED:
		return FEATUREBIT_FAILED
	default:
		return prev
	}
}

func FeatureBitStateAtHeightFromWindowCounts(
	d FeatureBitDeployment,
	height uint64,
	windowSignalCounts []uint32,
) (FeatureBitEval, error) {
	if err := d.Validate(); err != nil {
		return FeatureBitEval{}, err
	}

	boundaryHeight := height - (height % SIGNAL_WINDOW)
	targetBoundaryIndex := boundaryHeight / SIGNAL_WINDOW

	needWindows := int(targetBoundaryIndex)
	if len(windowSignalCounts) < needWindows {
		return FeatureBitEval{}, fmt.Errorf(
			"featurebits: need %d window_signal_counts entries, got %d",
			needWindows,
			len(windowSignalCounts),
		)
	}

	state := FEATUREBIT_DEFINED
	for boundaryIndex := uint64(0); boundaryIndex <= targetBoundaryIndex; boundaryIndex++ {
		bh := boundaryIndex * SIGNAL_WINDOW
		var prevCnt uint32
		if bh < SIGNAL_WINDOW {
			prevCnt = 0
		} else {
			prevCnt = windowSignalCounts[boundaryIndex-1]
		}
		state = evalFeatureBitsNextState(state, bh, prevCnt, d)
	}

	var prevCnt uint32
	if boundaryHeight < SIGNAL_WINDOW {
		prevCnt = 0
	} else {
		prevCnt = windowSignalCounts[targetBoundaryIndex-1]
	}

	return FeatureBitEval{
		State:               state,
		BoundaryHeight:      boundaryHeight,
		PrevWindowSignalCnt: prevCnt,
		SignalWindow:        SIGNAL_WINDOW,
		SignalThreshold:     SIGNAL_THRESHOLD,
	}, nil
}
