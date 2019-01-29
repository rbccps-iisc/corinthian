const owner_sidebar = angular.module("owner_sidebar", []);

owner_sidebar.controller('owner_sidebarCtrl', function($scope, $http){
    $scope.sidebar = [
    	{"text":"ADD Entity","href":window.location.origin+"/ui/pages/owner/", "legend":"ni ni-fat-add", "color":"green"},
    	{"text":"Catalog","href": window.location.origin+"/ui/pages/owner/catalog/", "legend":"ni ni-pin-3", "color":"orange"},
    	{"text":"Follow","href":window.location.origin+"/ui/pages/owner/follow/", "legend":"ni ni-send", "color":"blue"},
    	{"text":"Follow Status","href":window.location.origin+"/ui/pages/owner/follow-status/", "legend":"fas fa-info-circle", "color":"dark green"},
    	{"text":"Follow Requests","href":window.location.origin+"/ui/pages/owner/catalog/follow-requests", "legend":"ni ni-bell-55", "color":"red"},
    ];
});
