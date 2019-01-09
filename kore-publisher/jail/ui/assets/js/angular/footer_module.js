const footer = angular.module("footer", []);

footer.controller('footerCtrl', function($scope, $http){
    $scope.copyright_year = "2018";
    $scope.copyright_owner = {"name":"RBCCPS, IISc Bangalore", "href":"http://www.rbccps.org/"};
    $scope.footer_links = [
    	{"text":"RBCCPS","href":"http://www.rbccps.org/"},
    	{"text":"About Us","href":"#"},
    	{"text":"Blog","href":"#"},
    	{"text":"License","href":"#"}
    ]
});