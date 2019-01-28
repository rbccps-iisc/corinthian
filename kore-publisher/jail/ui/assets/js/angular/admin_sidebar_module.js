const admin_sidebar = angular.module("admin_sidebar", []);

admin_sidebar.controller('admin_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	{"text":"ADD Owner","href":window.location.origin+"/ui/pages/admin/", "legend":"fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/admin/catalog/", "legend":"pin-3", "color":"orange"},
    	{"text":"Link-1","href":"#", "legend":"fat-add", "color":"green"}
    ];
});
