const ui_urls = angular.module("ui_urls", []);
// const origin = "https://localhost"
const api = {
	"admin": {
		"register-owner": "/admin/register-owner",
		"deregister-owner": "/admin/deregister-owner",
		"block": "/admin/block",
		"unblock": "/admin/unblock",
		"login": "/admin/owners",
		"reset-apikey": "/admin/reset-apikey"
	},
	"owner": {
		"follow": "/owner/follow",
		"block": "/owner/block",
		"unblock": "/owner/unblock",
		"unfollow": "/owner/unfollow",
		"share": "/owner/share",
		"bind": "/owner/bind",
		"unbind": "/owner/unbind",
		"permissions": "owner/permissions",
		"reject-follow": "/owner/reject-follow",
		"follow-status": "/owner/follow-status",
		"follow-requests": "/owner/follow-requests",
		"register-entity": "/owner/register-entity",
		"deregister-entity": "/owner/deregister-entity",
		"set-autonomous": "/owner/set-autonomous",
		"reset-apikey": "/owner/reset-apikey",
		"login": "/owner/entities"
	},
	"entity": {
		"follow": "/entity/follow",
		"block": "/entity/block",
		"unfollow": "/entity/unfollow",
		"share": "/entity/share",
		"bind": "/entity/bind",
		"unbind": "/entity/unbind",
		"permissions": "entity/permissions",
		"reject-follow": "/entity/reject-follow",
		"follow-status": "/entity/follow-status",
		"follow-requests": "/entity/follow-requests",
		"login": "/entity/permissions"
	},
	"general_apis": {
		"catalog": "/catalog"
	}
}

ui_urls.controller('uiURLCtrl', function($scope, $http){
    $scope.origin = origin;
    $scope.api = api;
});

ui_urls.value("origin"  , origin);
ui_urls.value("api"  , api);
