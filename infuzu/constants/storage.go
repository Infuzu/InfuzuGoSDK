package infuzu

import utils "InfuzuGOSDK/infuzu/utils"

var IAuthTokenHeaderName = utils.PreconfiguredGetEnv("INFUZU_AUTH_TOKEN_HEADER_NAME", "I-Auth-Token")

var DefaultRequestTimeout = utils.PreconfiguredGetEnv("DEFAULT_REQUEST_TIMEOUT", "30")

var ClockwiseBaseUrl = utils.PreconfiguredGetEnv("CLOCKWISE_BASE_URL", "https://clockwise.infuzu.com/")

var ClockwiseRetrieveAssignmentEndpoint = utils.PreconfiguredGetEnv(
	"CLOCKWISE_RETRIEVE_ASSIGNMENT_ENDPOINT",
	"assignment/",
)

var ClockwiseAssignmentCompleteEndpoint = utils.PreconfiguredGetEnv(
	"CLOCKWISE_ASSIGNMENT_COMPLETE_ENDPOINT",
	"task-completed/",
)
var ClockwiseCreateRuleEndpoint = utils.PreconfiguredGetEnv(
	"CLOCKWISE_CREATE_RULE_ENDPOINT",
	"rule/create/",
)
var ClockwiseDeleteRuleEndpoint = utils.PreconfiguredGetEnv(
	"CLOCKWISE_DELETE_RULE_ENDPOINT",
	"rule/delete/<str:rule_id>/",
)
var ClockwiseRuleLogsEndpoint = utils.PreconfiguredGetEnv(
	"CLOCKWISE_RULE_LOGS_ENDPOINT",
	"rule/logs/<str:rule_id>/",
)

var IKeysBaseUrl = utils.PreconfiguredGetEnv("INFUZU_KEYS_BASE_URL", "https://keys.infuzu.com/")
var IKeysKeyPairEndpoint = utils.PreconfiguredGetEnv(
	"INFUZU_KEYS_KEY_PAIR_ENDPOINT",
	"api/key/<str:key_id>/",
)

var CogitobotBaseUrl = utils.PreconfiguredGetEnv("COGITOBOT_BASE_URL", "https://cogitobot.infuzu.com/")
var CogitobotRetrieveDocumentVersionEndpoint = utils.GetEnv(
	"COGITOBOT_RETRIEVE_DOCUMENT_VERSION_ENDPOINT",
	"internal/document-version/<str:document_version_id>/",
)

var AccessBaseUrl = utils.PreconfiguredGetEnv("ACCESS_BASE_URL", "https://accounts.infuzu.com/")
var AccessRetrieveObjectAccessProfileEndpoint = utils.GetEnv(
	"ACCESS_RETRIEVE_OBJECT_ACCESS_PROFILE_ENDPOINT",
	"access/object-access-profile/<str:user_id>/<str:object_type>/",
)
var AccessRetrieveUserAccessProfileEndpoint = utils.PreconfiguredGetEnv(
	"ACCESS_RETRIEVE_USER_ACCESS_PROFILE_ENDPOINT",
	"access/user-access-profile/<str:user_id>/",
)

var DefaultAccessInstanceAccessProfileEndpoint = utils.PreconfiguredGetEnv(
	"DEFAULT_ACCESS_INSTANCE_ACCESS_PROFILE_ENDPOINT",
	"access/instance-access-profile/",
)
var AccessCreateInstanceAccessProfileEndpoint = utils.PreconfiguredGetEnvFactory(
	"ACCESS_CREATE_INSTANCE_ACCESS_PROFILE_ENDPOINT",
	DefaultAccessInstanceAccessProfileEndpoint,
)
var AccessRetrieveInstanceAccessProfileEndpoint = utils.PreconfiguredGetEnvFactory(
	"ACCESS_RETRIEVE_INSTANCE_ACCESS_PROFILE_ENDPOINT",
	func() string {
		return DefaultAccessInstanceAccessProfileEndpoint() + "<str:instance_id>/"
	},
)
var AccessDeleteInstanceAccessProfileEndpoint = utils.PreconfiguredGetEnvFactory(
	"ACCESS_DELETE_INSTANCE_ACCESS_PROFILE_ENDPOINT",
	func() string {
		return DefaultAccessInstanceAccessProfileEndpoint() + "<str:instance_id>/"
	},
)

var SubscriptionsBaseURL = utils.PreconfiguredGetEnv("SUBSCRIPTIONS_BASE_URL", "https://accounts.infuzu.com/")
var SubscriptionsRetrieveSubscriptions = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_SUBSCRIPTIONS",
	"subscriptions/subscriptions/",
)
var SubscriptionsRetrieveSubscription = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_SUBSCRIPTION",
	"subscriptions/subscription/<str:subscription_id>/",
)
var SubscriptionsRetrieveSubscriptionOverview = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_SUBSCRIPTION_OVERVIEW",
	"subscriptions/overview/<str:start_time>/<str:end_time>/",
)
var SubscriptionsRetrieveSubscriptionFreeTrial = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_SUBSCRIPTION_FREE_TRIAL",
	"subscriptions/subscription-free-trial/<str:subscription_id>/<str:user_id>/",
)
var SubscriptionsCreateSubscriptionFreeTrial = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_CREATE_SUBSCRIPTION_FREE_TRIAL",
	"subscriptions/subscription-free-trial/<str:subscription_id>/<str:user_id>/",
)
var SubscriptionsSubscribeToPlan = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_SUBSCRIBE_TO_PLAN",
	"subscriptions/plan/<str:subscription_plan_id>/subscribe/<str:user_id>/",
)
var SubscriptionsRetrieveUserSubscriptions = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_USER_SUBSCRIPTIONS",
	"subscriptions/user-subscriptions/",
)
var SubscriptionsCreateUserSubscription = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_CREATE_USER_SUBSCRIPTION",
	"subscriptions/user-subscriptions/",
)
var SubscriptionsRetrieveUserSubscription = utils.PreconfiguredGetEnv(
	"SUBSCRIPTIONS_RETRIEVE_USER_SUBSCRIPTION",
	"subscriptions/user-subscription/<str:user_subscription_id>/",
)

var UsersBaseURL = utils.PreconfiguredGetEnv("USERS_BASE_URL", "https://accounts.infuzu.com/")
var UsersRetrieveUserEndpoint = utils.PreconfiguredGetEnv(
	"USERS_RETRIEVE_USER_ENDPOINT",
	"users/user/<str:user_id>/",
)
