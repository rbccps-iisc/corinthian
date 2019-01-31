const footer = angular.module("footer", []);

footer.controller('footerCtrl', function($scope, $http){
	$scope.copyright_legend = "fas fa-code"; //far fa-copyright
    $scope.copyright_start_year = "2018";
    $scope.copyright_end_year = new Date().getFullYear();
    $scope.copyright_owner = {"name":"", "href":""};
    // $scope.copyright_owner = {"name":"RBCCPS, IISc Bangalore", "href":"http://www.rbccps.org/"};
    $scope.footer_links = [
    	{"text":"Overview","href":"http://www.iudx.org.in/overview/"},
    	{"text":"Use Cases","href":"http://www.iudx.org.in/use-cases/"},
    	// {"text":"Partners","href":"http://www.iudx.org.in/collaboration/partners/"},
    	{"text":"Contact","href":"http://www.iudx.org.in/contact/"},
    	// {"text":"News","href":"http://www.iudx.org.in/smart-city-data-news/"},
    	{"text":"Tech Specs","href":"https://docs.google.com/document/d/1ep7xI2E-B1qiPBtonbAHaZezx_eBx_KTBwMRrzjCr44/edit"},
    	// {"text":"License","href":"#"}
    ]
});