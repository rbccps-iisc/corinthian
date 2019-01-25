const owner = angular.module("owner", ['session_checker', 'footer', 'logout', 'ui_urls', 'owner_sidebar']);

var d;
var SCOPE;

owner.controller('ownerCtrl', function($scope, $compile, $http){
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

    SCOPE = $scope;
    $scope.compile_and_prepend = function (elem_from, elem_to) {
        var content = $compile(angular.element(elem_from))($scope);
        angular.element(elem_to).prepend(content);
    }
    
    // ADD/Register Entity
    $scope.addEntity=function(){
      //console.log($scope.is_autonomous==undefined)
      // console.log($scope.is_autonomous)
      var is_autonomous=($scope.is_autonomous==undefined || $scope.is_autonomous==false)?false:true;
      $http({
          method: 'POST',
          url: api['owner']['register-entity'],
          headers: {
              'id': $scope.id,
              'apikey': $scope.apikey,
              'entity': $scope.entity_name,
              'is-autonomous':is_autonomous
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
                    var _obj = {'ent':$scope.id+"/"+$scope.entity_name, 'is_autonomous':is_autonomous, 'index': $scope.id+"_"+$scope.entity_name}
                    data.push(_obj);
                    localStorage.setItem('data', JSON.stringify(data));
                    // console.log(JSON.parse(localStorage.getItem('data')))
                    var entity_row=`<tr id="`+_obj['index']+`">
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
                      <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#reset_passwd_modal`+_obj['index']+`
                      ">
                        Reset Password  | <i class="fas fa-key"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="reset_passwd_modal`+_obj['index']+`" tabindex="-1" role="dialog" aria-labelledby="reset_passwd_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="exampleModalLabel`+_obj['ent']+`">Reset Password</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="reset_password_modal_body`+_obj['index']+`" class="modal-body">
                              <center>Are you sure you want to reset the password for <br><strong>`+_obj['ent']+`</strong>?</center>
                            </div>
                            <div id="reset_password_modal_footer`+_obj['index']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-primary" onclick="entity_reset_password('`+_obj['ent']+`', '`+_obj['index']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-default" data-toggle="modal" data-target="#block_modal`+_obj['index']+`">
                        Block | <i class="fas fa-ban"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="block_modal`+_obj['index']+`" tabindex="-1" role="dialog" aria-labelledby="block_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="block_modal_label`+_obj['ent']+`">Block Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="block_modal_body`+_obj['index']+`" class="modal-body">
                              <center>Are you sure you want to block <br><strong>`+_obj['ent']+`</strong>?</center>
                            </div>
                            <div id="block_modal_footer`+_obj['index']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-default"  onclick="entity_block('`+_obj['ent']+`', '`+_obj['index']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-outline-default" data-toggle="modal" data-target="#unblock_modal`+_obj['index']+`">
                        UnBlock | <i class="far fa-circle"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="unblock_modal`+_obj['index']+`" tabindex="-1" role="dialog" aria-labelledby="unblock_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="unblock_modal_label`+_obj['ent']+`">UnBlock Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="unblock_modal_body`+_obj['index']+`" class="modal-body">
                              <center>Are you sure you want to unblock <br><strong>`+_obj['ent']+`</strong>?</center>
                            </div>
                            <div id="unblock_modal_footer`+_obj['index']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-outline-default"  onclick="entity_unblock('`+_obj['ent']+`', '`+_obj['index']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-danger" data-toggle="modal" data-target="#delete_modal`+_obj['index']+`">
                        Delete | <i class="far fa-trash-alt"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="delete_modal`+_obj['index']+`" tabindex="-1" role="dialog" aria-labelledby="delete_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="delete_modal_label`+_obj['ent']+`">Delete Entity</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="delete_modal_body`+_obj['index']+`" class="modal-body">
                              <center>Are you sure you want to delete <br><strong>`+_obj['ent']+`</strong>?</center>
                            </div>
                            <div id="delete_modal_footer`+_obj['index']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-danger" onclick="entity_delete('`+_obj['ent']+`', '`+_obj['index']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                     
                    <td>
                              <label class="custom-toggle">
                                <input type="checkbox" onchange="change_autonomous_state('`+_obj['ent']+`','`+_obj['index']+`',this)" `+ checker(_obj['is_autonomous']) +`>
                                <span class="custom-toggle-slider rounded-circle"></span>
                              </label>
                            </td>
                    
                  </tr>`;

                  var compiled_entity_row=$compile(entity_row)($scope);
                    $("#entity_list").each(function() {
                        if ($(this).html()){
                            $(this).prepend(compiled_entity_row);
                        }else{
                            $(this).append(compiled_entity_row);
                        }
                    });

                    // $("cb_"+ _obj['index']).prop('checked', _obj['is_autonomous'])
                    $("#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show in" role="alert">
                            <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
                            <span class="alert-inner--text"><strong>Success! </strong>` + _obj['ent'] + ` registered.</span>
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>`);
                    window.setTimeout(function(){
                      $( "#alert_message").fadeIn();
                      $( "#alert_message").fadeOut(450);
                    }, 900);
                  

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
                      $( "#alert_message").fadeOut(450);
                    }, 900);
            });
    }
});