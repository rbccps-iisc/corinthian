const owner_sidebar = angular.module("owner_sidebar", []);

owner_sidebar.controller('owner_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	{"text":"ADD Entity","href":"#", "legend":"fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/owner/catalog/", "legend":"pin-3", "color":"orange"},
    	{"text":"Link-1","href":"#", "legend":"fat-add", "color":"green"}
    ];
});
