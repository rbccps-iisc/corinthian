const owner = angular.module("owner", ['session_checker', 'footer', 'logout', 'ui_urls', 'owner_sidebar']);

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
	                	$( "#"+ entity['index']).fadeOut(1, function() { $(this).remove(); });
	                	$("#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show in" role="alert">
												    <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
												    <span class="alert-inner--text"><strong>Success! </strong>` + entity['ent'] + ` deleted.</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
	                	// $( "#alert_message").fadeOut();
	                	
	                	window.setTimeout(function(){
	                		$( "#delete_modal"+ entity['index']).modal('hide');
	                		$('.modal-backdrop').remove();
	                	}, 1);
	                	window.setTimeout(function(){
	                		$( "#alert_message").fadeIn();
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
	                	break;
                	}
                }
                
            }, function(error){
                 // console.log(error['data']['error']); 
                 $( "#alert_message").html(`<br><div class="alert alert-danger alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="fas fa-exclamation-triangle"></i></span>
												    <span class="alert-inner--text"><strong>Error! </strong>` + error['data']['error'] + `</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
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
            	$( "#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
												    <span class="alert-inner--text"><strong>Success! </strong>` + entity['ent'] + ` blocked.</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
	        	window.setTimeout(function(){
	        		$( "#block_modal"+ entity['index']).modal('hide');
	        		$('.modal-backdrop').remove();
	        	}, 100);    
	        	window.setTimeout(function(){
	                		$( "#alert_message").fadeIn(250);
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
    	    	       
            }, function(error){
                 // console.log(error['data']['error']); 
                 $( "#alert_message").html(`<br><div class="alert alert-danger alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="fas fa-exclamation-triangle"></i></span>
												    <span class="alert-inner--text"><strong>Error! </strong>` + error['data']['error'] + `</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
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
            	$( "#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
												    <span class="alert-inner--text"><strong>Success! </strong>` + entity['ent'] + ` unblocked.</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
	        	window.setTimeout(function(){
	        		$( "#unblock_modal"+ entity['index']).modal('hide');
	        		$('.modal-backdrop').remove();
	        	}, 100);   
	        	window.setTimeout(function(){
	                		$( "#alert_message").fadeIn(250);
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
            	        
            }, function(error){
                 // console.log(error['data']['error']); 
                 $( "#alert_message").html(`<br><div class="alert alert-danger alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="fas fa-exclamation-triangle"></i></span>
												    <span class="alert-inner--text"><strong>Error! </strong>` + error['data']['error'] + `</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
        });
	}

});