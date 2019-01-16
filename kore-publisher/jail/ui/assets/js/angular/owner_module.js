const owner = angular.module("owner", ['session_checker', 'footer', 'logout', 'ui_urls']);

var d;

owner.controller('ownerCtrl', function($scope, $http){
    $scope.brand = "IUDX";
    $scope.brand_full_form = "Indian Urban Data Exchange";
    $scope.navbar_links = [
    	{"text":"Link-1","href":"#", "legend":"planet"},
    	{"text":"Link-2","href":"#", "legend":"compass-04"},
    	{"text":"Link-3","href":"#", "legend":"diamond"}
    ];
   
    $scope.data = JSON.parse(localStorage.getItem('data'));    
    $scope.id = sessionStorage.getItem('id');
    $scope.apikey = sessionStorage.getItem('apikey');
    d=$scope.data
    
    // Delete/Deregister Entity
    $scope.entity_delete=function(entity, index){
    	$http({
			    method: 'POST',
			    url: api['owner']['deregister-entity'],
			    headers: {
			        'id': $scope.id,
			        'apikey': $scope.apikey,
			        'entity': entity['ent'],
			    },
			    data: {} 
			}).then(function (response)
            {
                var temp_d = {'ent':entity['ent'], 'is-autonomous': entity['is_autonomous']}
                for (var i = 0; i < d.length ; i++) {
                	if (d[i]['ent']==entity['ent']){
	                	d.splice(i, 1);
	                	localStorage.setItem('data', JSON.stringify(d));
	                	$( "#"+ entity['index']).fadeOut(150, function() { $(this).remove(); });
	                	window.setTimeout(function(){
	                		$( "#delete_modal"+ entity['index']).modal('hide');
	                		$('.modal-backdrop').remove();
	                	}, 100);
                	}
                }
                
            }, function(error){
                 console.log(error['data']['error']); 
        });
	}

    // Block Entity
    $scope.entity_block=function(entity, index){
    	$http({
			    method: 'POST',
			    url: api['owner']['block'],
			    headers: {
			        'id': $scope.id,
			        'apikey': $scope.apikey,
			        'entity': entity['ent'],
			    },
			    data: {} 
			}).then(function (response)
            {
	        	window.setTimeout(function(){
	        		$( "#block_modal"+ entity['index']).modal('hide');
	        		$('.modal-backdrop').remove();
	        	}, 100);            
            }, function(error){
                 console.log(error['data']['error']); 
        });
	}

    // UnBlock Entity
    $scope.entity_unblock=function(entity, index){
    	$http({
			    method: 'POST',
			    url: api['owner']['unblock'],
			    headers: {
			        'id': $scope.id,
			        'apikey': $scope.apikey,
			        'entity': entity['ent'],
			    },
			    data: {} 
			}).then(function (response)
            {
	        	window.setTimeout(function(){
	        		$( "#unblock_modal"+ entity['index']).modal('hide');
	        		$('.modal-backdrop').remove();
	        	}, 100);            
            }, function(error){
                 console.log(error['data']['error']); 
        });
	}

});