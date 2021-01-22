$('.master-menu').click(function(e) {
	e.preventDefault();
	$(this).next('ul').slideToggle('slow');
	$('.child-menu').not($(this).next()).slideUp('slow');
});

$('#btn-sidebar').click(function(e) {
	e.preventDefault();
	$('#wrapper').toggleClass('toggled');
	$('#btn-sidebar').toggleClass('toggled');
});