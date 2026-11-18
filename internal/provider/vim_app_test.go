package provider_test

import (
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const vimAppResource = "slackapp_vim_app.test"

type vimAppConfig struct {
	name      string
	scopes    []string
	icon      string
	consumers []string
}

func (c vimAppConfig) hcl(slack *fakeSlack, vim *fakeVim) string {
	icon := "null"
	if c.icon != "" {
		icon = fmt.Sprintf("%q", c.icon)
	}

	return fmt.Sprintf(`
provider "slackapp" {
  base_url          = %q
  service_token     = "xoxp-service"
  vim_client_id     = "client"
  vim_client_secret = "secret"
}

resource "slackapp_vim_app" "test" {
  manifest = jsonencode({
    display_information = { name = %q }
    features            = { bot_user = { display_name = %q } }
    oauth_config        = { scopes = { bot = %s } }
  })
  icon_path         = %s
  vim_base_url      = %q
  vim_account_id    = "acc-1"
  vault_secret_name = "slack-app/test"
  vault_consumers   = %s
}
`, slack.baseURL(), c.name, c.name, hclList(c.scopes), icon, vim.baseURL(), hclList(c.consumers))
}

func hclList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}

	return "[" + strings.Join(quoted, ", ") + "]"
}

// vimAppIcon writes a square PNG of side pixels in one colour, and returns
// its path and SHA-256.
func vimAppIcon(t *testing.T, side int, shade uint8) (string, string) {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, side, side))
	for x := range side {
		for y := range side {
			img.Set(x, y, color.RGBA{R: shade, G: 128, B: 128, A: 255})
		}
	}

	file := filepath.Join(t.TempDir(), fmt.Sprintf("icon-%d.png", shade))
	out, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(out, img); err != nil {
		t.Fatal(err)
	}
	_ = out.Close()

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	return file, fmt.Sprintf("%x", sha256.Sum256(data))
}

// vimAppCheckNoSecretsInState checks that no attribute in state holds the
// bot token or signing secret of any app the fake created.
func vimAppCheckNoSecretsInState(slack *fakeSlack) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for n := 1; n <= 5; n++ {
			appID := fakeSlackAppID(n)
			for _, rs := range s.RootModule().Resources {
				for key, value := range rs.Primary.Attributes {
					if strings.Contains(value, fakeSlackBotToken(appID)) || strings.Contains(value, fakeSlackSigningSecret(appID)) {
						return fmt.Errorf("state attribute %s holds a secret of %s", key, appID)
					}
				}
			}
		}

		return nil
	}
}

// vimAppCheckSecret checks the vault secret holds the credentials of the
// nth app and is shared with consumers.
func vimAppCheckSecret(vim *fakeVim, n int, consumers ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		token, secret := vim.secret("slack-app/test")
		if secret == nil {
			return fmt.Errorf("the vault has no secret slack-app/test")
		}

		appID := fakeSlackAppID(n)
		if secret.fields["botToken"] != fakeSlackBotToken(appID) || secret.fields["signingSecret"] != fakeSlackSigningSecret(appID) {
			return fmt.Errorf("the vault secret does not hold the credentials of %s", appID)
		}

		got := slices.Clone(secret.consumers)
		slices.Sort(got)
		if !slices.Equal(got, consumers) {
			return fmt.Errorf("the vault secret is shared with %v, want %v", got, consumers)
		}

		return resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(vimAppResource, "vault_secret_token", token),
			resource.TestCheckResourceAttr(vimAppResource, "bot_token_ref", token+"@botToken"),
			resource.TestCheckResourceAttr(vimAppResource, "signing_secret_ref", token+"@signingSecret"),
			resource.TestCheckResourceAttr(vimAppResource, "bot_token_sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(fakeSlackBotToken(appID))))),
		)(s)
	}
}

func vimAppCheckCalls(slack *fakeSlack, method string, want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if got := slack.callCount(method); got != want {
			return fmt.Errorf("%s called %d times, want %d", method, got, want)
		}

		return nil
	}
}

// Every step is followed by a plan that must be empty.
func TestAccVimApp_lifecycle(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	icon1, sum1 := vimAppIcon(t, 512, 10)
	icon2, sum2 := vimAppIcon(t, 600, 20)
	appID := fakeSlackAppID(1)

	base := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, icon: icon1, consumers: []string{"agentflow:staging/jim"}}
	renamed := base
	renamed.name = "Jim Two"
	widened := renamed
	widened.scopes = []string{"chat:write", "im:history"}
	newIcon := widened
	newIcon.icon = icon2
	reshared := newIcon
	reshared.consumers = []string{"agentflow:staging/jim", "agentflow:staging/oscar"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		CheckDestroy: func(*terraform.State) error {
			if slack.appCount() != 0 {
				return fmt.Errorf("Slack still has an app after destroy")
			}
			if _, secret := vim.secret("slack-app/test"); secret == nil {
				return fmt.Errorf("destroy deleted the vault secret, which the platform app may not do")
			}

			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: base.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "id", appID),
					resource.TestCheckResourceAttr(vimAppResource, "team_id", "T1"),
					resource.TestCheckResourceAttr(vimAppResource, "bot_user_id", "U"+appID),
					resource.TestCheckResourceAttr(vimAppResource, "bot_id", "B"+appID),
					resource.TestCheckResourceAttr(vimAppResource, "icon_sha256", sum1),
					resource.TestCheckResourceAttrSet(vimAppResource, "icon_image_url"),
					vimAppCheckSecret(vim, 1, "agentflow:staging/jim"),
					vimAppCheckNoSecretsInState(slack),
					vimAppCheckCalls(slack, "apps.developerInstall", 1),
					func(*terraform.State) error {
						if got := slack.iconsSet(appID); !slices.Equal(got, []string{sum1}) {
							return fmt.Errorf("icons set %v, want one", got)
						}

						return nil
					},
				),
			},
			{
				// A rename keeps the scopes: no install.
				Config: renamed.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckCalls(slack, "apps.manifest.create", 1),
					vimAppCheckCalls(slack, "apps.developerInstall", 1),
					vimAppCheckCalls(slack, "apps.icon.set", 1),
				),
			},
			{
				Config: widened.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckCalls(slack, "apps.developerInstall", 2),
					vimAppCheckSecret(vim, 1, "agentflow:staging/jim"),
				),
			},
			{
				Config: newIcon.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "icon_sha256", sum2),
					func(*terraform.State) error {
						if got := slack.iconsSet(appID); !slices.Equal(got, []string{sum1, sum2}) {
							return fmt.Errorf("icons set %v, want two", got)
						}

						return nil
					},
				),
			},
			{
				Config: reshared.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckSecret(vim, 1, "agentflow:staging/jim", "agentflow:staging/oscar"),
					func(*terraform.State) error {
						want := []string{"POST /api/vault/secrets", "PUT /api/vault/secrets/:token/consumers"}
						if got := vim.routes(); !slices.Equal(got, want) {
							return fmt.Errorf("vault calls %v, want %v", got, want)
						}

						return nil
					},
				),
			},
			{
				Config:  reshared.hcl(slack, vim),
				Destroy: true,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(vimAppResource, plancheck.ResourceActionDestroy)},
				},
			},
		},
	})
}

// The icon changed in Slack's settings shows as drift, and applying sets it
// again.
func TestAccVimApp_iconDrift(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	icon, _ := vimAppIcon(t, 512, 10)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, icon: icon}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig: slack.changeIcon,
				Config:    config.hcl(slack, vim),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(vimAppResource, plancheck.ResourceActionUpdate)},
				},
				Check: vimAppCheckCalls(slack, "apps.icon.set", 2),
			},
		},
	})
}

func TestAccVimApp_badIcon(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	small, _ := vimAppIcon(t, 511, 10)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      vimAppConfig{name: "Jim", icon: small}.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`511x511 pixels; Slack takes 512 to 2000 pixels per side`),
			},
		},
	})

	if slack.callCount("apps.manifest.create") != 0 {
		t.Error("a bad icon created an app; it must fail the plan")
	}
}

// When install fails, the app is deleted: its signing secret would
// otherwise be lost.
func TestAccVimApp_installFails(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	slack.failWith("apps.developerInstall", map[string]any{"ok": false, "error": "invalid_scopes"})
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      config.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`Failed to install the Slack app`),
			},
			{
				PreConfig: func() {
					if slack.appCount() != 0 {
						t.Error("the app outlived a failed install")
					}
					slack.succeed("apps.developerInstall")
				},
				Config: config.hcl(slack, vim),
				Check:  vimAppCheckSecret(vim, 2),
			},
		},
	})
}

// When the vault write fails, the app is deleted, and the next apply
// creates it again.
func TestAccVimApp_vaultWriteFails(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	vim.failWith("POST /api/vault/secrets", 403)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      config.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`Failed to write the Slack app's credentials to the vault`),
			},
			{
				PreConfig: func() {
					if slack.appCount() != 0 {
						t.Error("the app outlived a failed vault write")
					}
					vim.succeed("POST /api/vault/secrets")
				},
				Config: config.hcl(slack, vim),
				Check:  vimAppCheckSecret(vim, 2),
			},
		},
	})
}

func TestAccVimApp_secretNameTaken(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{Config: config.hcl(slack, vim), Destroy: true},
			{
				Config:      config.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`already has a secret named "slack-app/test"`),
			},
		},
	})

	if slack.appCount() != 0 {
		t.Error("the app outlived a refused vault write")
	}
}

// An app deleted in Slack is created again in place, and its new
// credentials go to the same vault secret.
func TestAccVimApp_deletedInSlack(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, consumers: []string{"agentflow:staging/jim"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig: func() { applicationResourceDeleteInSlack(t, slack, 1) },
				Config:    config.hcl(slack, vim),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(vimAppResource, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "id", fakeSlackAppID(2)),
					vimAppCheckSecret(vim, 2, "agentflow:staging/jim"),
					vimAppCheckNoSecretsInState(slack),
				),
			},
		},
	})
}

// A failed icon set leaves the app and its secret, and the next plan sets
// the icon again.
func TestAccVimApp_iconFails(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	slack.failWith("apps.icon.set", map[string]any{"ok": false, "error": "invalid_icon_size"})
	icon, sum := vimAppIcon(t, 512, 10)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, icon: icon}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:             config.hcl(slack, vim),
				ExpectNonEmptyPlan: true,
				Check:              resource.TestCheckNoResourceAttr(vimAppResource, "icon_sha256"),
			},
			{
				PreConfig: func() { slack.succeed("apps.icon.set") },
				Config:    config.hcl(slack, vim),
				Check:     resource.TestCheckResourceAttr(vimAppResource, "icon_sha256", sum),
			},
		},
	})
}

func TestAccVimApp_consumersFail(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}
	shared := config
	shared.consumers = []string{"agentflow:staging/jim"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig:   func() { vim.failWith("PUT /api/vault/secrets/:token/consumers", 403) },
				Config:      shared.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`Failed to set the services the vault secret is shared with`),
			},
			{
				PreConfig: func() { vim.succeed("PUT /api/vault/secrets/:token/consumers") },
				Config:    shared.hcl(slack, vim),
				Check:     vimAppCheckSecret(vim, 1, "agentflow:staging/jim"),
			},
		},
	})
}
