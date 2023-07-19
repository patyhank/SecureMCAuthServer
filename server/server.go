package server

import (
	"SecureAuthServer/Auth"
	"SecureAuthServer/GMMAuth"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var LogBuffer bytes.Buffer

func deriveKey(passphrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 2000, 32, sha256.New), salt
}

func EncStruct(passphrase string, account Account) {
	marshal, err := json.Marshal(account)
	if err != nil {
		log.Println(err)
	}
	os.WriteFile("credentials", encrypt(passphrase, marshal), 0644)
}

func DecStruct(passphrase string) *Account {
	var acc Account
	if _, err := os.Stat("credentials"); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	file, err := os.ReadFile("credentials")
	if err != nil {
		log.Println(err)
		return nil
	}
	data := decrypt(passphrase, file)
	err = json.Unmarshal(data, &acc)
	return &acc
}

func encrypt(passphrase string, rawData []byte) []byte {
	key, salt := deriveKey(passphrase, nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, rawData, nil)

	return bytes.Join([][]byte{salt, iv, data}, []byte("EOD\n"))
}

func decrypt(passphrase string, ciphertext []byte) []byte {
	arr := bytes.Split(ciphertext, []byte("EOD\n"))
	salt := arr[0]
	iv := arr[1]
	data := arr[2]
	key, _ := deriveKey(passphrase, salt)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data, _ = aesgcm.Open(nil, iv, data, nil)
	return data
}

type AccountInfo struct {
	Username  string          `json:"Username"`
	Password  string          `json:"Password"`
	AuthCache *GMMAuth.MSauth `json:"Cache,omitempty"`
}
type Account map[string]AccountInfo

var tokenMap = sync.Map{}

func CheckPasswordRight(pass string) bool {
	var acc Account
	if _, err := os.Stat("credentials"); errors.Is(err, os.ErrNotExist) {
		EncStruct(pass, Account{})
		return true
	}
	file, err := os.ReadFile("credentials")
	if err != nil {
		log.Println(err)
		return false
	}
	data := decrypt(pass, file)
	err = json.Unmarshal(data, &acc)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func loadingAccountData(pass, usercode string) *Auth.Auth {
	var acc Account
	if _, err := os.Stat("credentials"); errors.Is(err, os.ErrNotExist) {
		log.Println("credentials not found, please add some account info")
		return nil
	}
	file, err := os.ReadFile("credentials")
	if err != nil {
		log.Println(err)
		return nil
	}
	data := decrypt(pass, file)
	json.Unmarshal(data, &acc)
	if _, ok := acc[usercode]; !ok {
		return nil
	}
	accData := acc[usercode]
	cache := accData.AuthCache
	if cache != nil {
		if err := GMMAuth.CheckRefreshMS(cache); err == nil {
			accData.AuthCache = cache
			acc[usercode] = accData
			EncStruct(pass, acc)
			ms, err := GMMAuth.GetMCcredentialsByMS(cache)
			if err == nil {
				return &ms
			}
		}
	}
	cache, err = GMMAuth.GetPasswordMS(accData.Username, accData.Password)
	if err != nil {

		log.Println(err)
		return nil
	}
	accData.AuthCache = cache
	acc[usercode] = accData
	EncStruct(pass, acc)
	ms, err := GMMAuth.GetMCcredentialsByMS(cache)
	if err != nil {
		log.Println(err)
		//logFile(err.Error())
		return nil
	}
	return &ms
}

func ServeAuth(passphrase string, chOut bool) {
	if chOut {
		log.SetOutput(&LogBuffer)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	as := r.Group("/as")
	as.POST("/authenticate", func(c *gin.Context) {
		var payload authPayload
		c.BindJSON(&payload)
		log.Printf("[Session Auth Requesting] %s\n", payload.UserName)
		auth := loadingAccountData(passphrase, payload.UserName)

		if auth == nil {
			log.Printf("[Failed] %s\n", payload.UserName)
			c.AbortWithStatusJSON(400, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Forbidden",
			})
			return
		}
		log.Printf("[Logged] %s\n", payload.UserName)
		profile := Profile{
			ID:   auth.UUID,
			Name: auth.Name,
		}
		astk := uuid.NewString()
		tokenMap.Store(astk, auth)
		c.JSON(200, authResp{
			Tokens: Tokens{
				AccessToken: astk,
				ClientToken: "",
			},
			AvailableProfiles: []Profile{profile},
			SelectedProfile:   profile,
		})
	})
	as.POST("/refresh", func(c *gin.Context) {
		var re refreshPayload
		c.BindJSON(&re)

		c.JSON(200, authResp{
			Tokens: Tokens{
				AccessToken: re.AccessToken,
				ClientToken: re.AccessToken,
			},
			AvailableProfiles: []Profile{
				*re.SelectedProfile,
			},
			SelectedProfile: *re.SelectedProfile,
		})
	})
	as.POST("/validate", func(c *gin.Context) {
		c.Status(204)
	})
	as.POST("/signout", func(c *gin.Context) {
		c.Status(200)
	})
	as.POST("/invalidate", func(c *gin.Context) {
		c.Status(200)
	})
	ss := r.Group("/ss")
	ss.POST("/session/minecraft/join", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		var req request
		err := json.Unmarshal(body, &req)
		if err != nil {
			var reqa requestAlt

			err := json.Unmarshal(body, &reqa)
			if err != nil {
				c.AbortWithStatusJSON(403, gin.H{
					"error":        "ForbiddenOperationException",
					"errorMessage": "Invalid credentials.",
				})
				fmt.Println(err)
				return
			}
			req = request{
				AccessToken:     reqa.AccessToken,
				SelectedProfile: reqa.SelectedProfile.ID,
				ServerID:        reqa.ServerID,
			}
		}
		authD, ok := tokenMap.Load(req.AccessToken)
		if !ok {
			c.AbortWithStatusJSON(403, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Invalid credentials. Invalid username or password.",
			})
			return
		}
		authData := authD.(*Auth.Auth)
		err = LoginRemote(request{
			AccessToken:     authData.AsTk,
			SelectedProfile: strings.ReplaceAll(authData.UUID, "-", ""),
			ServerID:        req.ServerID,
		})
		if err != nil {
			c.AbortWithStatusJSON(403, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Login Remote Failed.",
			})
			return
		}
		c.Status(204)
	})
	r.POST("/getUser", func(c *gin.Context) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		user := buf.String()
		data := loadingAccountData(passphrase, user)
		if data == nil {
			c.AbortWithStatus(400)
			return
		}

		tokenMap.Store(data.Name, data)
		c.Data(200, "text/plain", []byte(data.Name))
		log.Printf("[getUser] Code [%v]: %v\n", user, data.Name)
	})
	r.POST("/login", func(c *gin.Context) {
		//reloadAccount()
		result, _ := io.ReadAll(c.Request.Body)
		var req ReqBody
		err := json.Unmarshal(result, &req)
		if err != nil {
			log.Printf("[login] Request with bad payload\n")
			c.Status(403)
			return
		}
		log.Printf("[login] Request Code [%v] login\n", req.User)
		value, loaded := tokenMap.LoadAndDelete(req.User)
		if !loaded {
			log.Printf("[login] Request with empty cache payload\n")
			c.Status(403)
			return
		}
		auth := value.(*Auth.Auth)

		err = Auth.LoginAuth(*auth, req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
		if err != nil {
			c.AbortWithStatus(400)
			return
		}
		log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(refresh)")
		c.Status(200)
	})

	r.Run("127.0.0.1:37565")
}
func LoginRemote(req request) error {
	client := http.Client{}
	requestPacket, err := json.Marshal(
		req,
	)
	if err != nil {
		return fmt.Errorf("create request packet to yggdrasil faile: %v", err)
	}

	PostRequest, err := http.NewRequest(http.MethodPost, "https://sessionserver.mojang.com/session/minecraft/join",
		bytes.NewReader(requestPacket))
	if err != nil {
		return fmt.Errorf("make request error: %v", err)
	}
	PostRequest.Header.Set("User-agent", "go-mc")
	PostRequest.Header.Set("Connection", "keep-alive")
	PostRequest.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(PostRequest)
	if err != nil {
		return fmt.Errorf("post fail: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("auth fail: %s", string(body))
	}
	return nil

}

type ReqBody struct {
	User        string `json:"user"`
	ShareSecret string `json:"shareSecret"`
	ServerID    string `json:"serverID"`
	PublicKey   string `json:"publicKey"`
	VerifyToken string `json:"verifyToken"`
}

type Error struct {
	Err    string `json:"error"`
	ErrMsg string `json:"errorMessage"`
	Cause  string `json:"cause"`
}

func (e Error) Error() string {
	return e.Err + ": " + e.ErrMsg + ", " + e.Cause
}

// agent is a struct of auth
type agent struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

type proof struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// Tokens store AccessToken and ClientToken
type Tokens struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

var defaultAgent = agent{
	Name:    "Minecraft",
	Version: 1,
}

// authPayload is a yggdrasil request struct
type authPayload struct {
	Agent agent `json:"agent"`
	proof
	ClientToken string `json:"clientToken,omitempty"`
	RequestUser bool   `json:"requestUser"`
}

// authResp is the response from Mojang's auth server
type authResp struct {
	Tokens
	AvailableProfiles []Profile `json:"availableProfiles"` // only present if the agent field was received

	SelectedProfile Profile `json:"selectedProfile"` // only present if the agent field was received
	User            struct {
		// only present if requestUser was true in the request authPayload
		ID         string `json:"id"` // hexadecimal
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
	} `json:"user"`

	*Error
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Legacy bool   `json:"legacy"` // we don't care
}
type refreshPayload struct {
	Tokens
	SelectedProfile *Profile `json:"selectedProfile,omitempty"`

	RequestUser bool `json:"requestUser"`
}

type profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type request struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}
type requestAlt struct {
	AccessToken     string  `json:"accessToken"`
	SelectedProfile profile `json:"selectedProfile"`
	ServerID        string  `json:"serverId"`
}
