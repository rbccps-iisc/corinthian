const ui_urls = angular.module("ui_urls", []);
const origin = "https://localhost:443"
const api = {
	"admin": {
		"register-owner": "/admin/register-owner",
		"deregister-owner": "/admin/deregister-owner",
		"block": "/admin/block",
		"unblock": "/admin/unblock",
		"login": "/admin/owner"
	},
	"owner": {
		"follow": "/owner/follow",
		"block": "/owner/block",
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
		"login": "/owner/entities/"
	},
	"auto-entity": {
		"follow": "/owner/follow",
		"block": "/owner/block",
		"unfollow": "/owner/unfollow",
		"share": "/owner/share",
		"bind": "/owner/bind",
		"unbind": "/owner/unbind",
		"permissions": "owner/permissions",
		"reject-follow": "/owner/reject-follow",
		"follow-status": "/owner/follow-status",
		"follow-requests": "/owner/follow-requests"
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