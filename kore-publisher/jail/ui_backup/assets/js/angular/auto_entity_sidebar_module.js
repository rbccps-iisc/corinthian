const auto_entity_sidebar = angular.module("auto_entity_sidebar", []);

auto_entity_sidebar.controller('auto_entity_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	// {"text":"Link-1","href":window.location.origin+"/ui/pages/auto_entity/", "legend":"fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/auto_entity/catalog/", "legend":"pin-3", "color":"orange"},
    	{"text":"Link-1","href":"#", "legend":"fat-add", "color":"green"}
    ];
});
