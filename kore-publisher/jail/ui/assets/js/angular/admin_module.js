const admin = angular.module("admin", ['session_checker', 'footer', 'logout', 'ui_urls', 'admin_sidebar']);

var d;
var SCOPE;

admin.controller('adminCtrl', function($scope, $compile, $http){
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
    
    // ADD/Register owner
    $scope.addOwner=function(){
      
      $http({
          method: 'POST',
          url: api['admin']['register-owner'],
          headers: {
              'id': $scope.id,
              'apikey': $scope.apikey,
              'owner': $scope.owner_name,
          },
          data: {} 
      }).then(function (response)
            {
  
                    var data=JSON.parse(localStorage.getItem('data'));
                    var _obj = {'own':$scope.owner_name}
                    data.push(_obj);
                    localStorage.setItem('data', JSON.stringify(data));
                    // console.log(JSON.parse(localStorage.getItem('data')))
                    var owner_row=`<tr id="`+_obj['own']+`">
                    <th scope="row">
                      <div class="media align-items-center">
                        <a href="#" class="avatar rounded-circle mr-3">
                          <img alt="Image placeholder" src="../../assets/img/logo/owner-1.png">
                        </a>
                        <div class="media-body">
                          <span class="mb-0 text-sm">`+_obj['own']+`</span>
                        </div>
                      </div>
                    </th>
                    <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#reset_passwd_modal`+_obj['own']+`
                      ">
                        Reset Password  | <i class="fas fa-key"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="reset_passwd_modal`+_obj['own']+`" tabindex="-1" role="dialog" aria-labelledby="reset_passwd_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="exampleModalLabel`+_obj['own']+`">Reset Password</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="reset_password_modal_body`+_obj['own']+`" class="modal-body">
                              <center>Are you sure you want to reset the password for <br><strong>`+_obj['own']+`</strong>?</center>
                            </div>
                            <div id="reset_password_modal_footer`+_obj['own']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-primary" onclick="owner_reset_password('`+_obj['own']+`', '`+_obj['own']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-default" data-toggle="modal" data-target="#block_modal`+_obj['own']+`">
                        Block | <i class="fas fa-ban"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="block_modal`+_obj['own']+`" tabindex="-1" role="dialog" aria-labelledby="block_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="block_modal_label`+_obj['own']+`">Block Owner</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="block_modal_body`+_obj['own']+`" class="modal-body">
                              <center>Are you sure you want to block <br><strong>`+_obj['own']+`</strong>?</center>
                            </div>
                            <div id="block_modal_footer`+_obj['own']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-default"  onclick="owner_block('`+_obj['own']+`', '`+_obj['own']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-outline-default" data-toggle="modal" data-target="#unblock_modal`+_obj['own']+`">
                        UnBlock | <i class="far fa-circle"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="unblock_modal`+_obj['own']+`" tabindex="-1" role="dialog" aria-labelledby="unblock_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="unblock_modal_label`+_obj['own']+`">UnBlock Owner</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="unblock_modal_body`+_obj['own']+`" class="modal-body">
                              <center>Are you sure you want to unblock <br><strong>`+_obj['own']+`</strong>?</center>
                            </div>
                            <div id="unblock_modal_footer`+_obj['own']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-outline-default"  onclick="owner_unblock('`+_obj['own']+`', '`+_obj['own']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                      <td>
                      <!-- Button trigger modal -->
                      <button type="button" class="btn btn-danger" data-toggle="modal" data-target="#delete_modal`+_obj['own']+`">
                        Delete | <i class="far fa-trash-alt"></i>
                      </button>

                      <!-- Modal -->
                      <div class="modal fade" id="delete_modal`+_obj['own']+`" tabindex="-1" role="dialog" aria-labelledby="delete_modal_label" aria-hidden="true">
                        <div class="modal-dialog modal-dialog-centered" role="document">
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="delete_modal_label`+_obj['own']+`">Delete Owner</h5>
                              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                              </button>
                            </div>
                            <div id="delete_modal_body`+_obj['own']+`" class="modal-body">
                              <center>Are you sure you want to delete <br><strong>`+_obj['own']+`</strong>?</center>
                            </div>
                            <div id="delete_modal_footer`+_obj['own']+`" class="modal-footer">
                              <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-thumbs-down"></i></button>
                              <button type="button" class="btn btn-danger" onclick="owner_delete('`+_obj['own']+`', '`+_obj['own']+`')"><i class="fas fa-thumbs-up"></i></button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    
                  </tr>`;

                  var compiled_owner_row=$compile(owner_row)($scope);
                    $("#owner_list").each(function() {
                        if ($(this).html()){
                            $(this).prepend(compiled_owner_row);
                        }else{
                            $(this).append(compiled_owner_row);
                        }
                    });

                    // $("cb_"+ _obj['own']).prop('checked', _obj['is_autonomous'])
                    $("#alert_message").html(`<br><div class="alert alert-success alert-dismissible fade show in" role="alert">
                            <span class="alert-inner--icon"><i class="ni ni-like-2"></i></span>
                            <span class="alert-inner--text"><strong>Success! </strong>` + _obj['own'] + ` registered.</span>
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