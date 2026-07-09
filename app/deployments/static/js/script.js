// Toggles visibility of dependent form fields
function hideOrShow(el) {
  var fname = hideOrShow.name.toLowerCase();
  var selector = $(el).data(fname + '-selector');
  var search_id = '[' + selector + ']';

  var pattern = $(el).data(fname + '-' + el.value.toString() + '-pattern');
  var re = new RegExp(pattern);

  $(search_id).each(function () {
    if (this.id !== el.id){
      $(this).parent().closest('div').attr('hidden', true);

      if ( re.test(this.id) ) {
        $(this).parent().closest('div').attr('hidden', false);
      }
    }
  });
};

// Check password double time.
function checkSecretMatch(input) {
  var confirmInput = document.getElementById(input.id + '_confirm');
  var msg = document.getElementById(input.id.replace('_confirm', '') + '_match_msg');
  if (!confirmInput || !msg) return;

  var baseInput = document.getElementById(input.id.replace('_confirm', ''));

  if (!confirmInput.value) {
    msg.textContent = '';
    msg.classList.remove('text-danger');
    confirmInput.setCustomValidity('');
    return;
  }
  if (baseInput.value !== confirmInput.value) {
    msg.textContent = 'Passwords do not match.';
    msg.classList.add('text-danger');
    confirmInput.setCustomValidity('Passwords do not match.');
  } else {
    msg.textContent = 'Passwords match.';
    msg.classList.remove('text-danger');
    confirmInput.setCustomValidity('');
  }
}

$(document).on('input', 'input[data-type="secret"]', function () {
  var id = this.id.endsWith('_confirm') ? this.id.replace('_confirm', '') : this.id;
  var mainInput = document.getElementById(id);
  checkSecretMatch(mainInput);
})
