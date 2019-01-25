const error_page = angular.module("error_page", []);

error_page.controller('error_pageCtrl', function($scope, $http){
    $scope.error = {
    	"_403":{"title":"403 : Access Forbidden","text":"You have tried to access a page you are not supposed to.","href":window.location.origin+"/ui/pages/login/"},
    	"_404":{"title":"Catalog","text":"","href": window.location.origin+"/ui/pages/login/"},
    	{"title":"Link-1","text":"","href":"#"}
    };
});
