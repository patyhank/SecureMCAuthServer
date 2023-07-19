package main

import (
	"SecureAuthServer/server"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/pflag"
	"maps"
	"os"
	"regexp"
	"sort"
	"time"
)

var passphrase string

func init() {
	pflag.StringVarP(&passphrase, "pass", "p", "", "Auth-Server MainKey")
	pflag.Parse()
}

type FormData struct {
	userCode, username, password string
}

func main() {
	if passphrase != "" {
		server.ServeAuth(passphrase, false)
		return
	}
	alert := ""
	retryCount := 0
PASSWORD:
	{
		if retryCount > 3 {
			os.Exit(0)
		}
		application := tview.NewApplication()
		application.EnableMouse(true)
		inputField := tview.NewInputField().
			SetLabel("請輸入啟動密碼: ").
			SetFieldWidth(30).
			SetLabelColor(tcell.ColorWhite).
			SetMaskCharacter('*').
			SetDoneFunc(func(key tcell.Key) {
				application.Stop()
			})
		if alert != "" {
			inputField.SetTitle(alert)
			inputField.SetTitleColor(tcell.ColorRed)
		}
		application.SetRoot(inputField, true).EnableMouse(true).SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			application.Sync()
			return event
		}).SetMouseCapture(func(event *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
			application.Sync()
			return event, action
		}).Run()
		passphrase = inputField.GetText()
		if passphrase == "" {
			alert = "密碼不得為空"
			retryCount++
			goto PASSWORD
		}
		if !server.CheckPasswordRight(passphrase) {
			alert = "密碼錯誤"
			retryCount++

			goto PASSWORD
		}
	}

	go func() {
		server.ServeAuth(passphrase, true)
	}()
	app := tview.NewApplication()
	form := tview.NewForm()
	newForm(&FormData{}, form)
	list := tview.NewList()
	list.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		app.Sync()
		return action, event
	})
	form.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		app.Sync()
		return action, event
	})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			{
				list.Clear()
				accountS := server.DecStruct(passphrase)
				if accountS == nil {
					return
				}
				account := *accountS
				keys := maps.Keys(account)
				sort.Strings(keys)
				for _, uCode := range keys {
					info := account[uCode]
					list.AddItem(uCode, info.Username, 0, func() {
						newForm(&FormData{
							userCode: uCode,
							username: info.Username,
							password: info.Password,
						}, form)
					})
				}
			}
			<-ticker.C
		}
	}()
	logView := tview.NewTextView()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			logView.SetText(server.LogBuffer.String())

			<-ticker.C
		}
	}()
	grid := tview.NewGrid().SetColumns(30, 0, 60).SetBorders(true).AddItem(form, 0, 0, 1, 1, 0, 0, true).AddItem(list, 0, 1, 1, 1, 0, 0, false).AddItem(logView, 0, 2, 1, 1, 0, 0, false)
	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		fmt.Println(err)
	}

}
func newForm(data *FormData, form *tview.Form) {
	form.Clear(true)
	userCodeRegex := regexp.MustCompile("^[A-Za-z0-9]*$")
	inputField := tview.NewInputField().SetLabel("使用者代號").SetText(data.userCode).SetFieldWidth(10).SetAcceptanceFunc(func(text string, ch rune) bool {
		if userCodeRegex.MatchString(text) {
			return true
		}
		return false
	}).SetDisabled(data.userCode != "")
	form.AddFormItem(inputField)
	form.AddInputField("帳號", data.username, 30, nil, nil)
	form.AddPasswordField("密碼", data.password, 30, '*', nil)
	form.AddButton("儲存", func() {
		accountS := server.DecStruct(passphrase)
		if accountS == nil {
			return
		}
		account := *accountS
		usercode := form.GetFormItem(0).(*tview.InputField)
		username := form.GetFormItem(1).(*tview.InputField)
		password := form.GetFormItem(2).(*tview.InputField)
		account[usercode.GetText()] = server.AccountInfo{
			Username:  username.GetText(),
			Password:  password.GetText(),
			AuthCache: nil,
		}
		server.EncStruct(passphrase, account)
	})
	form.AddButton("移除", func() {
		accountS := server.DecStruct(passphrase)
		if accountS == nil {
			return
		}
		account := *accountS
		usercode := form.GetFormItem(0).(*tview.InputField)
		delete(account, usercode.GetText())
		server.EncStruct(passphrase, account)
	})
	form.AddButton("建立新的", func() {
		newForm(&FormData{}, form)
	})

}
