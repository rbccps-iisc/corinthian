const entity_sidebar = angular.module("entity_sidebar", []);

entity_sidebar.controller('entity_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	// {"text":"Link-1","href":window.location.origin+"/ui/pages/entity/", "legend":"fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/entity/catalog/", "legend":"ni ni-pin-3", "color":"orange"},
    	{"text":"Link-1","href":"#", "legend":"ni ni-fat-add", "color":"green"}
    ];
});
