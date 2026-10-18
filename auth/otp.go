package auth

// ont-time-password (OTP) generation and verification

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"junglerider/gatekeeper/app"

	"github.com/go-chi/chi/v5"
	goqr "github.com/piglig/go-qr"
	"github.com/rs/zerolog/log"
	"github.com/xlzd/gotp"
)

type Controller struct {
	*app.BaseController
}

type OTPParams struct {
	Secret  string `json:"otpSecret"`
	Name    string `json:"name"`
	Service string `json:"service"`
}

func NewController(config *app.Config) *Controller {
	return &Controller{
		&app.BaseController{Config: config},
	}
}

// registers the OTP helper routes, which are stateless and need no protection
func (c *Controller) RegisterRoutes(public chi.Router, protected chi.Router) {
	public.Get("/otp/secret", c.genSecretHandler)
	public.Post("/otp/uri", c.genURIHandler)
	public.Post("/otp/qrcode", c.genQRCodeHandler)
}

// verifies a given OTP using the given secret
func VerifyOTP(otp string, secret string) bool {
	totp := gotp.NewDefaultTOTP(secret)
	return totp.Verify(otp, time.Now().Unix())
}

// generate a random TOTP secret
func (c *Controller) genSecretHandler(w http.ResponseWriter, r *http.Request) {
	response := make(map[string]any, 1)
	response["otpSecret"] = gotp.RandomSecret(20)
	c.DataReply(w, 200, response)
}

// generate an OTP URI for the given secret, user (name) and issuer (service)
func (c *Controller) genURIHandler(w http.ResponseWriter, r *http.Request) {
	params, err := getOTPParams(c, r)
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	response := make(map[string]any, 1)
	response["uri"] = otpParamsToURI(params)
	c.DataReply(w, 200, response)
}

// generate an OTP QR code in SVG format for the given secret, user (name) and issuer (service)
func (c *Controller) genQRCodeHandler(w http.ResponseWriter, r *http.Request) {
	params, err := getOTPParams(c, r)
	if err != nil {
		c.StatusReply(w, 400, err.Error())
		return
	}
	uri := otpParamsToURI(params)
	if qr, err := goqr.EncodeText(uri, goqr.High); err != nil {
		log.Error().Err(err).Msg("failed to generate QR code")
		c.StatusReply(w, 500)
	} else {
		config := goqr.NewQrCodeImgConfig(10, 4)
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		err = qr.WriteAsSVG(config, w, "#FFFFFF", "#000000")
		if err != nil {
			log.Error().Err(err)
		}
	}
}

// read and validate OTP parameters from request body
func getOTPParams(c *Controller, r *http.Request) (OTPParams, error) {
	var params OTPParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err == nil {
		err = errors.Join(
			c.ValidateString(params.Secret, "otp secret", 10, 255, true),
			c.ValidateString(params.Name, "user name", 1, 255, true),
			c.ValidateString(params.Service, "service/issuer", 1, 255, true),
		)
	}
	return params, err
}

// encode OTP parameters into an otpauth URI
func otpParamsToURI(otpParams OTPParams) string {
	return gotp.BuildUri(
		"totp",
		otpParams.Secret,
		otpParams.Name,
		otpParams.Service,
		"",
		0,
		6,
		30,
	)
}
