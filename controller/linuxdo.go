package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"one-api/common/config"
	"one-api/common/logger"
	"one-api/model"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	linuxDoTokenEndpoint = "https://connect.linux.do/oauth2/token"
	linuxDoUserEndpoint  = "https://connect.linux.do/api/user"
)

type LinuxDoOAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type LinuxDoUser struct {
	Id             int    `json:"id"`
	Username       string `json:"username"`
	Name           string `json:"name"`
	AvatarTemplate string `json:"avatar_template"`
	Active         bool   `json:"active"`
	TrustLevel     int    `json:"trust_level"`
}

func getLinuxDoUserInfoByCode(code string) (*LinuxDoUser, error) {
	if code == "" {
		return nil, errors.New("无效的参数")
	}
	if config.LinuxDoClientId == "" || config.LinuxDoClientSecret == "" {
		return nil, errors.New("LinuxDo OAuth 配置不完整")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", config.LinuxDoClientId)
	form.Set("client_secret", config.LinuxDoClientSecret)
	form.Set("code", code)

	req, err := http.NewRequest("POST", linuxDoTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		logger.SysError("无法连接至 LinuxDo 服务器(token), err:" + err.Error())
		return nil, errors.New("无法连接至 LinuxDo 服务器，请稍后重试！")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("无法连接至 LinuxDo 服务器，请稍后重试！")
	}

	var oauthResponse LinuxDoOAuthResponse
	err = json.NewDecoder(res.Body).Decode(&oauthResponse)
	if err != nil {
		return nil, err
	}
	if oauthResponse.AccessToken == "" {
		return nil, errors.New("返回值非法，access_token 为空，请稍后重试！")
	}

	req2, err := http.NewRequest("GET", linuxDoUserEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", oauthResponse.AccessToken))
	req2.Header.Set("Accept", "application/json")

	res2, err := client.Do(req2)
	if err != nil {
		logger.SysError("无法连接至 LinuxDo 服务器(user), err:" + err.Error())
		return nil, errors.New("无法连接至 LinuxDo 服务器，请稍后重试！")
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		return nil, errors.New("无法连接至 LinuxDo 服务器，请稍后重试！")
	}

	var linuxDoUser LinuxDoUser
	err = json.NewDecoder(res2.Body).Decode(&linuxDoUser)
	if err != nil {
		return nil, err
	}
	if linuxDoUser.Id == 0 {
		return nil, errors.New("返回值非法，用户 id 字段为空，请稍后重试！")
	}

	return &linuxDoUser, nil
}

func getUserByLinuxDo(linuxDoUser *LinuxDoUser) (user *model.User, err error) {
	linuxDoId := strconv.Itoa(linuxDoUser.Id)
	if model.IsLinuxDoIdAlreadyTaken(linuxDoId) {
		user, err = model.FindUserByField("linuxdo_id", linuxDoId)
		if err != nil {
			return nil, err
		}
	}
	return user, nil
}

func LinuxDoOAuth(c *gin.Context) {
	session := sessions.Default(c)
	state := c.Query("state")
	if state == "" || session.Get("oauth_state") == nil || state != session.Get("oauth_state").(string) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "state is empty or not same",
		})
		return
	}

	username := session.Get("username")
	if username != nil {
		LinuxDoBind(c)
		return
	}

	if !config.LinuxDoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 LinuxDo 登录以及注册",
		})
		return
	}

	code := c.Query("code")
	affCode := c.Query("aff")
	linuxDoUser, err := getLinuxDoUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	user, err := getUserByLinuxDo(linuxDoUser)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	linuxDoId := strconv.Itoa(linuxDoUser.Id)
	if user == nil {
		if !linuxDoUser.Active || linuxDoUser.TrustLevel < 1 {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "LinuxDo 账户未满足注册条件（active=true 且 trust_level>=1）",
			})
			return
		}
		if !config.RegisterEnabled {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}

		user = &model.User{
			LinuxDoId: linuxDoId,
			Role:      config.RoleCommonUser,
			Status:    config.UserStatusEnabled,
		}

		var inviterId int
		if affCode != "" {
			inviterId, _ = model.GetUserIdByAffCode(affCode)
		}
		if inviterId > 0 {
			user.InviterId = inviterId
		}

		user.Username = "linuxdo_" + linuxDoId

		if linuxDoUser.Name != "" {
			user.DisplayName = linuxDoUser.Name
		} else {
			user.DisplayName = user.Username
		}

		if err := user.Insert(inviterId); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	} else {
		user.LinuxDoId = linuxDoId
	}

	if user.Status != config.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}

	setupLogin(user, c)
}

func LinuxDoBind(c *gin.Context) {
	if !config.LinuxDoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 LinuxDo 登录以及注册",
		})
		return
	}

	code := c.Query("code")
	linuxDoUser, err := getLinuxDoUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	linuxDoId := strconv.Itoa(linuxDoUser.Id)
	if model.IsLinuxDoIdAlreadyTaken(linuxDoId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该 LinuxDo 账户已被绑定",
		})
		return
	}

	session := sessions.Default(c)
	id := session.Get("id")
	user := model.User{Id: id.(int)}
	err = user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	user.LinuxDoId = linuxDoId
	if user.AvatarUrl == "" && linuxDoUser.AvatarTemplate != "" {
		user.AvatarUrl = linuxDoUser.AvatarTemplate
	}

	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "bind",
	})
}
