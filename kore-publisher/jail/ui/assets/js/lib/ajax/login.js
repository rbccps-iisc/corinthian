admin_login_url = "/admin/owners"
owner_login_url = "/owner/entities/"
auto_entity_login_url = "/entity/"


function validateUser(){
	var id = $('#id');
	var apikey = $('#apikey');

	if(id=='admin'){
		//Trigger admin login
		/admin/owners
	}else if(id.includes('/')){
		//Trigger auto entity login
	}else{
		//Trigger owner login
	}

	console.log(id.val(), apikey.val());
}