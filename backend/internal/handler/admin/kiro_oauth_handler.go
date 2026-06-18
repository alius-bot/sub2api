package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type KiroOAuthHandler struct {
	kiroOAuthService *service.KiroOAuthService
}

func NewKiroOAuthHandler(kiroOAuthService *service.KiroOAuthService) *KiroOAuthHandler {
	return &KiroOAuthHandler{kiroOAuthService: kiroOAuthService}
}

type KiroDeviceAuthRequest struct {
	AuthType string `json:"auth_type"`
	Region   string `json:"region"`
	StartURL string `json:"start_url"`
	ProxyID  *int64 `json:"proxy_id"`
}

// StartDeviceAuth starts a Kiro device authorization flow
// POST /api/v1/admin/kiro/oauth/device-auth
func (h *KiroOAuthHandler) StartDeviceAuth(c *gin.Context) {
	var req KiroDeviceAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.kiroOAuthService.StartDeviceAuth(c.Request.Context(), service.KiroDeviceAuthInput{
		AuthType: req.AuthType,
		Region:   req.Region,
		StartURL: req.StartURL,
		ProxyID:  req.ProxyID,
	})
	if err != nil {
		response.InternalError(c, "启动设备授权失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

type KiroSocialAuthRequest struct {
	Provider    string `json:"provider"`
	Region      string `json:"region"`
	RedirectURI string `json:"redirect_uri"`
	ProxyID     *int64 `json:"proxy_id"`
}

// StartSocialAuth starts a Kiro social auth flow (Google/GitHub/Cognito)
// POST /api/v1/admin/kiro/oauth/social-auth
func (h *KiroOAuthHandler) StartSocialAuth(c *gin.Context) {
	var req KiroSocialAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.kiroOAuthService.StartSocialAuth(c.Request.Context(), service.KiroSocialAuthInput{
		Provider:    req.Provider,
		Region:      req.Region,
		RedirectURI: req.RedirectURI,
		ProxyID:     req.ProxyID,
	})
	if err != nil {
		response.InternalError(c, "启动社交登录失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

type KiroCompleteSocialRequest struct {
	SessionID      string `json:"session_id" binding:"required"`
	CallbackOrCode string `json:"callback_or_code" binding:"required"`
}

// CompleteSocialAuth completes a Kiro social auth flow with callback URL or code
// POST /api/v1/admin/kiro/oauth/complete-social
func (h *KiroOAuthHandler) CompleteSocialAuth(c *gin.Context) {
	var req KiroCompleteSocialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.kiroOAuthService.CompleteSocialAuth(c.Request.Context(), service.KiroCompleteSocialInput{
		SessionID:      req.SessionID,
		CallbackOrCode: req.CallbackOrCode,
	})
	if err != nil {
		response.BadRequest(c, "完成社交登录失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

type KiroSessionStatusRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// GetSessionStatus polls the status of a Kiro device auth session
// POST /api/v1/admin/kiro/oauth/session-status
func (h *KiroOAuthHandler) GetSessionStatus(c *gin.Context) {
	var req KiroSessionStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.kiroOAuthService.GetSessionStatus(c.Request.Context(), req.SessionID)
	if err != nil {
		response.BadRequest(c, "获取会话状态失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

type KiroCancelSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// CancelSession cancels a pending Kiro auth session
// POST /api/v1/admin/kiro/oauth/cancel-session
func (h *KiroOAuthHandler) CancelSession(c *gin.Context) {
	var req KiroCancelSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	if err := h.kiroOAuthService.CancelSession(req.SessionID); err != nil {
		response.BadRequest(c, "取消会话失败: "+err.Error())
		return
	}

	response.Success(c, nil)
}

// ScanTokens scans local Kiro IDE and AWS CLI cached tokens
// GET /api/v1/admin/kiro/oauth/scan-tokens
func (h *KiroOAuthHandler) ScanTokens(c *gin.Context) {
	result := h.kiroOAuthService.ScanTokens()
	response.Success(c, result)
}
