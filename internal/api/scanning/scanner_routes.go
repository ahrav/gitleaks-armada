package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ahrav/gitleaks-armada/internal/api/errs"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// ScannerConfig contains the dependencies needed by the scanner handlers.
type ScannerConfig struct {
	Log            *logger.Logger
	ScannerService *ScannerService
}

// ScannerRoutes binds all the scanner endpoints.
func ScannerRoutes(app *web.App, cfg ScannerConfig) {
	const version = "v1"

	app.HandlerFunc(http.MethodPost, version, "/scanners/groups", createScannerGroup(cfg))
}

// createScannerGroupRequest represents the payload for creating a scanner group.
type createScannerGroupRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Description string `json:"description,omitempty" validate:"max=500"`
}

// createScannerGroupResponse represents the response for creating a scanner group.
type createScannerGroupResponse struct {
	ScannerGroupInfo
}

// createScannerGroupConflictResponse represents the error response when a scanner group already exists.
type createScannerGroupConflictResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Encode implements the web.Encoder interface.
func (cgr createScannerGroupResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(cgr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (cgr createScannerGroupResponse) HTTPStatus() int { return http.StatusCreated } // 201

// Encode implements the web.Encoder interface.
func (cgcr createScannerGroupConflictResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(cgcr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (cgcr createScannerGroupConflictResponse) HTTPStatus() int { return http.StatusConflict } // 409

// createScannerGroup handles the request to create a scanner group.
func createScannerGroup(cfg ScannerConfig) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req createScannerGroupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		groupInfo, err := cfg.ScannerService.CreateScannerGroup(ctx, req.Name, req.Description)
		if err != nil {
			if errors.Is(err, ErrScannerGroupAlreadyExists) {
				return createScannerGroupConflictResponse{
					Code:    "conflict",
					Message: "A scanner group with this name already exists",
				}
			}
			return errs.New(errs.Internal, err)
		}

		return createScannerGroupResponse{*groupInfo}
	}
}
