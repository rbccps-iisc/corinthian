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
    
    // ADD/Register Entity
    $scope.addEntity=function(){
    	$http({
			    method: 'POST',
			    url: api['owner']['register-entity'],
			    headers: {
			        'id': $scope.id,
			        'apikey': $scope.apikey,
			        'entity': $scope.entity_name,
			        'is-autonomous':$scope.is_autonomous
			    },
			    data: {} 
			}).then(function (response)
            {

            			function checker(flag){
            				if(flag){
            					return 'checked'
            				}else{
            					return ''
            				}
            			}
                		
	                	var data=JSON.parse(localStorage.getItem('data'));
	                	var _obj = {'ent':$scope.id+"/"+$scope.entity_name, 'is_autonomous':$scope.is_autonomous, 'index': data.length}
	                	data.push(_obj);
	                	localStorage.setItem('data', JSON.stringify(data));
	                	$( "#entity_list" ).prepend( `<tr ng-repeat="x in data | orderBy:'-'" id="`+_obj['ent']+`">
                    <th scope="row">
                      <div class="media align-items-center">
                        <a href="#" class="avatar rounded-circle mr-3">
                          <img alt="Image placeholder" src="../../assets/img/logo/owner-1.png">
                        </a>
                        <div class="media-body">
                          <span class="mb-0 text-sm">`+_obj['ent']+`</span>
                        </div>
                      </div>
                    </th>
                    <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#reset_passwd_modal`+data.length+`
                      ">
                        Reset Password  | <i class="fas fa-key"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="reset_passwd_modal`+_obj['ent']+`" tabindex="-1" role="dialog" aria-labelledby="reset_passwd_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="exampleModalLabel`+_obj['ent']+`">Reset Password</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div class="modal-body">
                              Are you sure you want to reset the password for <strong>`+_obj['ent']+`</strong>?
                            </div>
                            <div class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-primary" ng-click="entity_reset_password('`+_obj['ent']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-default" data-toggle="modal" data-target="#block_modal`+data.length+`">
                        Block | <i class="fas fa-ban"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="block_modal`+data.length+`" tabindex="-1" role="dialog" aria-labelledby="block_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="block_modal_label`+_obj['ent']+`">Block Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div class="modal-body">
                              Are you sure you want to block <strong>`+_obj['ent']+`</strong>?
                            </div>
                            <div class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-default"  ng-click="entity_block(this.x, '`+data.length+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-outline-default" data-toggle="modal" data-target="#unblock_modal`+data.length+`">
                        UnBlock | <i class="far fa-circle"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="unblock_modal`+data.length+`" tabindex="-1" role="dialog" aria-labelledby="unblock_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="unblock_modal_label`+_obj['ent']+`">Block Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div class="modal-body">
                              Are you sure you want to unblock <strong>`+_obj['ent']+`</strong>?
                            </div>
                            <div class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-outline-default"  ng-click="entity_unblock(this.x, '`+data.length+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-danger" data-toggle="modal" data-target="#delete_modal`+data.length+`">
                        Delete | <i class="far fa-trash-alt"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="delete_modal`+data.length+`" tabindex="-1" role="dialog" aria-labelledby="delete_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="delete_modal_label`+_obj['ent']+`">Delete Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div class="modal-body">
                              Are you sure you want to delete <strong>`+_obj['ent']+`</strong>?
                            </div>
                            <div class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-danger" ng-click="entity_delete(`+_obj+`, '`+data.length+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                     
                    <td>
                      <label class="custom-toggle">
                        
                        <input type="checkbox" ` + checker($scope.is_autonomous) + `>
                        <span class="custom-toggle-slider rounded-circle"></span>
                      </label>
                    </td>
                    
                  </tr>` );
	                	$("#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show in" role="alert">
												    <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
												    <span class="alert-inner--text"><strong>Success! </strong>` + _obj[''] + ` registered.</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
	                	window.setTimeout(function(){
	                		$( "#alert_message").fadeIn();
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
	                

            }, function(error){
            	 $( "#alert_message").html(`<br><div class="alert alert-danger alert-dismissible fade show" role="alert">
												    <span class="alert-inner--icon"><i class="fas fa-exclamation-triangle"></i></span>
												    <span class="alert-inner--text"><strong>Error! </strong>` + error['data']['error'] + `</span>
												    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
												        <span aria-hidden="true">&times;</span>
												    </button>
												</div>`);
            	 window.setTimeout(function(){
	                		$( "#alert_message").fadeIn();
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
            });

			
    }

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
                 window.setTimeout(function(){
	                		$( "#alert_message").fadeIn(250);
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
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
                 window.setTimeout(function(){
	                		$( "#alert_message").fadeIn(250);
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
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
                 window.setTimeout(function(){
	                		$( "#alert_message").fadeIn(250);
	                		$( "#alert_message").fadeOut(750);
	                	}, 1);
        });
	}

});