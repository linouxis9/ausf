package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/sbi/consumer"
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

type confirmTestApp struct {
	*app.MockApp
	consumer *consumer.Consumer
}

func (a *confirmTestApp) Consumer() *consumer.Consumer { return a.consumer }

// A 5G AKA confirmation for an authentication that the UDM made EAP-AKA' must
// be refused: that context has no XRES*, which an empty RES* matched.
func TestAuth5gAkaConfirmRejectsEapAkaPrimeContext(t *testing.T) {
	const (
		supi   = "imsi-208930000000001"
		suci   = "suci-0-208-93-0000-0-0-0000000001"
		snName = "5G:mnc093.mcc208.3gppnetwork.org"
	)
	gin.SetMode(gin.TestMode)
	factory.AusfConfig = &factory.Config{
		Info: &factory.Info{Version: "1.0.3"},
		Configuration: &factory.Configuration{
			Sbi:    &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.9", Port: 8000},
			NrfUri: "http://nrf.test",
		},
	}
	ausf_context.Init()
	t.Cleanup(func() { ausf_context.GetSelf().RemoveUEAuthenticationContext(supi) })

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	gock.New("http://nrf.test").Get("/nnrf-disc/v1/nf-instances").Persist().Reply(http.StatusOK).
		JSON(map[string]interface{}{"nfInstances": []interface{}{map[string]interface{}{
			"nfInstanceId": "udm", "nfType": "UDM", "nfStatus": "REGISTERED",
			"nfServices": []interface{}{map[string]interface{}{
				"serviceInstanceId": "1", "serviceName": "nudm-ueau", "scheme": "http",
				"nfServiceStatus": "REGISTERED",
				"versions":        []interface{}{map[string]interface{}{"apiVersionInUri": "v1"}},
				"ipEndPoints":     []interface{}{map[string]interface{}{"ipv4Address": "127.0.0.3", "port": 8000}},
			}},
		}}})
	gock.New("http://127.0.0.3:8000").
		Post("/nudm-ueau/v1/" + suci + "/security-information/generate-auth-data").
		Reply(http.StatusOK).
		JSON(models.Udm_UEAU_AuthenticationInfoResult{
			AuthType: models.Udm_UEAU_AuthType_EAP_AKA_PRIME,
			Supi:     supi,
			AuthenticationVector: &models.Udm_UEAU_AuthenticationVector{
				AvType:  models.Udm_UEAU_AvType_EAP_AKA_PRIME,
				Rand:    "11111111111111111111111111111111",
				Autn:    "22222222222222222222222222222222",
				Xres:    "3333333333333333",
				CkPrime: "44444444444444444444444444444444",
				IkPrime: "55555555555555555555555555555555",
			},
		})
	gock.New("http://127.0.0.3:8000").Post("/nudm-ueau/v1/.*/auth-events").Persist().
		Reply(http.StatusCreated).JSON(models.Udm_UEAU_AuthEvent{})

	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(ausf_context.GetSelf()).AnyTimes()
	c, err := consumer.NewConsumer(mockApp)
	require.NoError(t, err)
	p, err := NewProcessor(&confirmTestApp{MockApp: mockApp, consumer: c})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	p.UeAuthPostRequestProcedure(ginCtx, models.Ausf_UEAU_AuthenticationInfo{
		SupiOrSuci:         suci,
		ServingNetworkName: snName,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var authCtx models.Ausf_UEAU_UEAuthenticationCtx
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &authCtx))
	_, path, _ := strings.Cut(authCtx.Links["eap-session"][0].Href, "/ue-authentications/")
	authCtxId := strings.TrimSuffix(path, "/eap-session")

	for _, tc := range []struct{ resStar, cause string }{
		{"", "MANDATORY_IE_INCORRECT"},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "USER_NOT_FOUND"},
	} {
		rec = httptest.NewRecorder()
		ginCtx, _ = gin.CreateTestContext(rec)
		resStar := tc.resStar
		p.Auth5gAkaComfirmRequestProcedure(ginCtx, models.Ausf_UEAU_ConfirmationData{ResStar: &resStar}, authCtxId)

		require.Equal(t, http.StatusBadRequest, rec.Code, "resStar %q: %s", tc.resStar, rec.Body.String())
		var problemDetails models.ProblemDetails
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problemDetails))
		require.Equal(t, tc.cause, problemDetails.Cause)
	}
}

func TestAuth5gAkaConfirmRejectsEmptyResStar(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	resStar := ""
	processor := &Processor{}
	processor.Auth5gAkaComfirmRequestProcedure(
		c,
		models.Ausf_UEAU_ConfirmationData{ResStar: &resStar},
		"suci-0-001-01-0000-0-0-0000000001",
	)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var problemDetails models.ProblemDetails
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &problemDetails))
	require.Equal(t, "MANDATORY_IE_INCORRECT", problemDetails.Cause)
}
