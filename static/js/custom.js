$('#login-button').click(function(){

	$('#login-button').hide(250);
	$('#login-form-front').fadeIn(250);

});

$('#get-result-button').click(function(){

	 $('.innerblockdown').css("position", "absolute");

	$('.innerblockdown').animate({
    'margin-left': '300px',
    'margin-top': '100px',
  	}, 2000);

});

$('.innerblockup').click(function(){

	$(this).css("position", "absolute");

	$(this).animate({
    'margin-left': '300px',
    'margin-top': '-74px',
  	}, 2000);

});