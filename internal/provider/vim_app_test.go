package provider_test

import (
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
)

const vimAppResource = "slackapp_vim_app.test"

type vimAppConfig struct {
	name      string
	scopes    []string
	icon      string
	consumers []string
	// collaborators is left unset when nil.
	collaborators []string
	// vimBaseURL replaces the fake Vim's URL.
	vimBaseURL string
}

func (c vimAppConfig) hcl(slack *fakeSlack, vim *fakeVim) string {
	icon := "null"
	if c.icon != "" {
		icon = fmt.Sprintf("%q", c.icon)
	}
	// Left out, not null, when unset: a provider older than the attribute
	// refuses it even null.
	collaborators := ""
	if c.collaborators != nil {
		collaborators = "collaborators = " + hclList(c.collaborators)
	}
	vimBaseURL := vim.baseURL()
	if c.vimBaseURL != "" {
		vimBaseURL = c.vimBaseURL
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
  %s
}
`, slack.baseURL(), c.name, c.name, hclList(c.scopes), icon, vimBaseURL, hclList(c.consumers), collaborators)
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
				ExpectError: regexp.MustCompile(`511x511\s+pixels;\s+Slack\s+takes\s+512\s+to\s+2000\s+pixels\s+per\s+side`),
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

// The platform app's client secret goes only to https, or to http on the
// loopback host.
func TestAccVimApp_badVimBaseURL(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)

	steps := []resource.TestStep{}
	for _, url := range []string{"http://api.getvim.ai", "https://user:pw@api.getvim.ai", "http://localhost@evil.example"} {
		steps = append(steps, resource.TestStep{
			Config:      vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, vimBaseURL: url}.hcl(slack, vim),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`must\s+be\s+https://\s+with\s+no\s+user\s+info,\s+or\s+http://\s+on\s+localhost\s+or\s+127\.0\.0\.1`),
		})
	}

	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: providerFactories, Steps: steps})

	if slack.appCount() != 0 || len(vim.routes()) != 0 {
		t.Error("a refused vim_base_url reached Slack or Vim")
	}
}

// A 409 to a repeated create may be this apply's own secret, so the app it
// may hold the credentials of is kept.
func TestAccVimApp_conflictAfterRetry(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	vim.failNext("POST /api/vault/secrets", http.StatusTooManyRequests, http.StatusConflict)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`The vault secret may hold this Slack app's credentials`),
			},
		},
	})

	if slack.appCount() != 1 {
		t.Errorf("%d apps, want the app kept", slack.appCount())
	}
}

// A recreate that lands in another workspace is refused: the secret keeps
// the credentials of the original app, and the new app is deleted.
func TestAccVimApp_recreateInAnotherWorkspace(t *testing.T) {
	providerUnsetEnvironment(t)
	fake, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(fake, vim)},
			{
				PreConfig: func() {
					_, err := applicationResourceSlackClient(fake).AppsManifestDelete(t.Context(),
						slack.AppsManifestDeleteRequest{AppID: fakeSlackAppID(1)})
					if err != nil {
						t.Fatal(err)
					}
					fake.moveTeam("T2")
				},
				Config:      config.hcl(fake, vim),
				ExpectError: regexp.MustCompile(`The Slack app would move to another workspace`),
			},
		},
	})

	if fake.appCount() != 0 {
		t.Error("the app created in the other workspace was kept")
	}
	if _, secret := vim.secret("slack-app/test"); secret == nil || secret.fields["botToken"] != fakeSlackBotToken(fakeSlackAppID(1)) {
		t.Error("the vault secret no longer holds the original app's credentials")
	}
}

// vimAppCheckCollaborators checks the app in state has the token's user and
// want as its owners in Slack, and nobody else.
func vimAppCheckCollaborators(slack *fakeSlack, want ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		all := []string{fakeSlackTokenOwner + ":owner"}
		for _, user := range want {
			all = append(all, user+":owner")
		}
		slices.Sort(all)
		appID := s.RootModule().Resources[vimAppResource].Primary.ID
		if got := slack.collaborators(appID); !slices.Equal(got, all) {
			return fmt.Errorf("Slack has collaborators %v, want %v", got, all)
		}

		return nil
	}
}

func vimAppExpectUpdate() []plancheck.PlanCheck {
	return []plancheck.PlanCheck{plancheck.ExpectResourceAction(vimAppResource, plancheck.ResourceActionUpdate)}
}

// Collaborators are added and removed to match the declared set, the token's
// user is kept and never listed, and one added in Slack shows as drift.
func TestAccVimApp_collaborators(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	appID := fakeSlackAppID(1)

	one := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}
	swapped := one
	swapped.collaborators = []string{"U002", "W003"}
	none := one
	none.collaborators = []string{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: one.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "collaborators.#", "1"),
					resource.TestCheckTypeSetElemAttr(vimAppResource, "collaborators.*", "U001"),
					vimAppCheckCollaborators(slack, "U001"),
				),
			},
			{
				Config: swapped.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckCollaborators(slack, "U002", "W003"),
					vimAppCheckCalls(slack, "apps.manifest.update", 0),
				),
			},
			{
				PreConfig:        func() { slack.addCollaborator(appID, "U009", "owner") },
				Config:           swapped.hcl(slack, vim),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: vimAppExpectUpdate()},
				Check:            vimAppCheckCollaborators(slack, "U002", "W003"),
			},
			{
				Config: none.hcl(slack, vim),
				Check:  vimAppCheckCollaborators(slack),
			},
		},
	})
}

// Declaring collaborators on an app that had none adds them, and unsetting
// the attribute stops managing them, leaving Slack as it is.
func TestAccVimApp_collaboratorsAddedThenUnset(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	unset := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}
	declared := unset
	declared.collaborators = []string{"U001"}
	listed := 0

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: unset.hcl(slack, vim)},
			{
				Config:           declared.hcl(slack, vim),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: vimAppExpectUpdate()},
				Check:            vimAppCheckCollaborators(slack, "U001"),
			},
			{
				Config: unset.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(vimAppResource, "collaborators.#"),
					vimAppCheckCollaborators(slack, "U001"),
				),
			},
			{
				PreConfig: func() {
					slack.addCollaborator(fakeSlackAppID(1), "U009", "owner")
					listed = slack.callCount("developer.apps.owners.list")
				},
				Config: unset.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckCollaborators(slack, "U001", "U009"),
					func(*terraform.State) error {
						return vimAppCheckCalls(slack, "developer.apps.owners.list", listed)(nil)
					},
				),
			},
		},
	})
}

// Unset, collaborators are left as they are and never listed.
func TestAccVimApp_collaboratorsUnset(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig: func() { slack.addCollaborator(fakeSlackAppID(1), "U009", "owner") },
				Config:    config.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(vimAppResource, "collaborators.#"),
					vimAppCheckCollaborators(slack, "U009"),
					vimAppCheckCalls(slack, "developer.apps.owners.list", 0),
				),
			},
		},
	})
}

// An app applied by 0.5.0, which has no collaborators, plans no change under
// this provider.
func TestAccVimApp_collaboratorsUpgradeFrom050(t *testing.T) {
	providerUnsetEnvironment(t)
	// The released provider and this one must share an address for the
	// second step to plan against the first one's state.
	t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "bookmd")
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, consumers: []string{"agentflow:staging/jim"}}

	resource.UnitTest(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"slackapp": {Source: "bookmd/slackapp", VersionConstraint: "0.5.0-bookmd.1"},
				},
				Config: config.hcl(slack, vim),
			},
			{
				ProtoV6ProviderFactories: providerFactories,
				Config: `
terraform {
  required_providers {
    slackapp = { source = "bookmd/slackapp" }
  }
}
` + config.hcl(slack, vim),
				PlanOnly: true,
			},
		},
	})
}

// The token's user owns the app, so declaring it is refused at plan, before
// anything is created.
func TestAccVimApp_collaboratorIsTokenOwner(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      vimAppConfig{name: "Jim", collaborators: []string{fakeSlackTokenOwner}}.hcl(slack, vim),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`A collaborator is the service token's user`),
			},
		},
	})

	if slack.appCount() != 0 {
		t.Error("an app was created with the token's user declared as a collaborator")
	}
}

// Declaring the token's user on an existing app is refused at plan, and
// changes nothing.
func TestAccVimApp_collaboratorIsTokenOwnerOnUpdate(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}
	owner := config
	owner.name = "Jim Two"
	owner.collaborators = []string{"U001", fakeSlackTokenOwner}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				Config:      owner.hcl(slack, vim),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`A collaborator is the service token's user`),
			},
			{
				Config: config.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					vimAppCheckCalls(slack, "apps.manifest.update", 0),
					vimAppCheckCollaborators(slack, "U001"),
				),
			},
		},
	})
}

// When Slack lists the token's user under another ID than auth.test gives,
// as an Enterprise Grid W ID beside a U ID could, nothing is removed and the
// listing is not recorded.
func TestAccVimApp_collaboratorsTokenOwnerNotListed(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}
	swapped := config
	swapped.collaborators = []string{"U002"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig:   func() { slack.listTokenOwnerAs("W0TOKENOWNER") },
				Config:      swapped.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`does\s+not\s+list\s+UTOKENOWNER`),
			},
			{
				PreConfig: func() {
					got, want := slack.collaborators(fakeSlackAppID(1)), []string{"U001:owner", fakeSlackTokenOwner + ":owner"}
					if !slices.Equal(got, want) {
						t.Errorf("Slack has collaborators %v, want %v", got, want)
					}
					if slack.callCount("developer.apps.owners.remove") != 0 {
						t.Error("a collaborator was removed while the token's user was not listed")
					}
				},
				Config:      swapped.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`does\s+not\s+list\s+UTOKENOWNER`),
			},
		},
	})
}

// A wanted reader is made an owner, and a reader not wanted is removed.
func TestAccVimApp_collaboratorsReaders(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	appID := fakeSlackAppID(1)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{}}.hcl(slack, vim)},
			{
				PreConfig: func() {
					slack.addCollaborator(appID, "U001", "reader")
					slack.addCollaborator(appID, "U009", "reader")
				},
				Config:           config.hcl(slack, vim),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: vimAppExpectUpdate()},
				Check:            vimAppCheckCollaborators(slack, "U001"),
			},
		},
	})
}

// A failed add on create keeps the app, and the next plan adds the
// collaborator again.
func TestAccVimApp_collaboratorsFail(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	slack.failWith("developer.apps.owners.add", map[string]any{"ok": false, "error": "invalid_user"})
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:             config.hcl(slack, vim),
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "id", fakeSlackAppID(1)),
					vimAppCheckSecret(vim, 1),
					vimAppCheckCollaborators(slack),
				),
			},
			{
				PreConfig: func() { slack.succeed("developer.apps.owners.add") },
				Config:    config.hcl(slack, vim),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(vimAppResource, "id", fakeSlackAppID(1)),
					vimAppCheckCollaborators(slack, "U001"),
				),
			},
		},
	})
}

// When create fails to set the collaborators and the next Read cannot list
// them, the plan still shows them to set, rather than taking them as set.
func TestAccVimApp_collaboratorsFailThenListFails(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	slack.failWith("developer.apps.owners.list", map[string]any{"ok": false, "error": "internal_error"})
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:             config.hcl(slack, vim),
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks:   resource.ConfigPlanChecks{PostApplyPostRefresh: vimAppExpectUpdate()},
				Check:              vimAppCheckCollaborators(slack),
			},
			{
				PreConfig: func() { slack.succeed("developer.apps.owners.list") },
				Config:    config.hcl(slack, vim),
				Check:     vimAppCheckCollaborators(slack, "U001"),
			},
		},
	})
}

// A failed update leaves the collaborators to set again, even when the next
// Read cannot list them.
func TestAccVimApp_collaboratorsUpdateFails(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}
	swapped := config
	swapped.collaborators = []string{"U002"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig: func() {
					slack.failWith("developer.apps.owners.add", map[string]any{"ok": false, "error": "invalid_user"})
				},
				Config:      swapped.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`Failed to set the Slack app's collaborators`),
			},
			{
				PreConfig: func() {
					slack.succeed("developer.apps.owners.add")
					slack.failWith("developer.apps.owners.list", map[string]any{"ok": false, "error": "internal_error"})
				},
				Config:             swapped.hcl(slack, vim),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: func() { slack.succeed("developer.apps.owners.list") },
				Config:    swapped.hcl(slack, vim),
				Check:     vimAppCheckCollaborators(slack, "U002"),
			},
		},
	})
}

// A collaborator already gone when removed counts as removed, and Slack
// refusing to remove the last owner fails the apply.
func TestAccVimApp_collaboratorsRemoveAnswers(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)
	config := vimAppConfig{name: "Jim", scopes: []string{"chat:write"}, collaborators: []string{"U001"}}
	none := config
	none.collaborators = []string{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config.hcl(slack, vim)},
			{
				PreConfig: func() {
					slack.failWith("developer.apps.owners.remove", map[string]any{"ok": false, "error": "user_not_found"})
				},
				Config:             none.hcl(slack, vim),
				ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: func() {
					slack.failWith("developer.apps.owners.remove", map[string]any{"ok": false, "error": "cannot_abandon_app"})
				},
				Config:      none.hcl(slack, vim),
				ExpectError: regexp.MustCompile(`cannot_abandon_app`),
			},
		},
	})
}

func TestAccVimApp_collaboratorNotAUserID(t *testing.T) {
	providerUnsetEnvironment(t)
	slack, vim := newFakeSlack(t), newFakeVim(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config:      vimAppConfig{name: "Jim", collaborators: []string{"someone@example.com"}}.hcl(slack, vim),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must\s+be\s+a\s+Slack\s+user\s+ID`),
			},
		},
	})
}
