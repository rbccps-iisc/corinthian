const admin_sidebar = angular.module("admin_sidebar", []);

admin_sidebar.controller('admin_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	{"text":"ADD Owner","href":window.location.origin+"/ui/pages/admin/", "legend":"ni ni-fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/admin/catalog/", "legend":"ni ni-pin-3", "color":"orange"},
    	{"text":"Link-1","href":"#", "legend":"ni ni-fat-add", "color":"green"}
    ];
});
