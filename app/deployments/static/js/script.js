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
function checkSecretMatch(baseInput) {
  var confirmInput = document.getElementById(baseInput.id + '_confirm');
  var msg = document.getElementById(baseInput.id + '_match_msg');
  if (!confirmInput || !msg) return true;

  if (!confirmInput.value) {
    msg.textContent = '';
    confirmInput.classList.remove('is-valid', 'is-invalid');
    confirmInput.setCustomValidity('');
    return true;
  }

  if (baseInput.value !== confirmInput.value) {
    msg.textContent = 'Passwords do not match.';
    msg.classList.add('text-danger');
    confirmInput.classList.remove('is-valid');
    confirmInput.classList.add('is-invalid');
    confirmInput.setCustomValidity('Passwords do not match.');
    return false;
  }

  msg.textContent = 'Passwords match.';
  msg.classList.remove('text-danger');
  confirmInput.classList.remove('is-invalid');
  confirmInput.classList.add('is-valid');
  confirmInput.setCustomValidity('');
  return true;
}

// live check while user is writing
$(document).on('input', 'input[data-type="secret"]', function () {
  var id = this.id.endsWith('_confirm') ? this.id.replace('_confirm', '') : this.id;
  var baseInput = document.getElementById(id);
  if (baseInput) checkSecretMatch(baseInput);
});

// stop the submit call if the secret check fails
$(document).on('submit', 'form', function (e) {
  var allMatch = true;

  $('input[data-type="secret"]').each(function () {
    if (this.id.endsWith('_confirm')) return;
    if (!checkSecretMatch(this)) {
      allMatch = false;
    }
  });

  if (!allMatch) {
    e.preventDefault();
  }
});
