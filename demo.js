function toggle_progress(elem) {
  var progress = document.getElementById('progressContainer');
  if (elem.checked) {
    //progress.style.visibility = "visible";
    progress.style.display = "block";
  } else {
    //progress.style.visibility = "hidden";
    progress.style.display = "none";
  }
}

function set_progress(out_of_100) {
  var progress = document.getElementById('progress');
  progress.style.width = out_of_100 + "%";
}

function set_iters(elem) {
  var iters = document.getElementById('iterations')
  if (elem.value == 'custom') {
    if (!iters.disabled) {
      return;
    }
    iters.disabled = false;
    iters.focus();
    iters.select();
  } else {
    iters.disabled = true;
    iters.value = elem.value;
  }
}

var status_callback = function(fraction_done) {
  set_progress(fraction_done * 100);
};

var result_callback = function(key, elapsed) {
  set_progress(100);
  var text = "created in " + elapsed + "s";
  document.getElementById("time").innerHTML = text;

  var keyInput = document.getElementById('key');
  keyInput.value = key;
  keyInput.focus();
  keyInput.select();

  document.getElementById('form').submit.disabled = false;
};

function generate() {
  var form = document.getElementById('form');
  form.submit.disabled = true;
  try {
    passforge.config(form.length.value, form.iterations.value,
                     status_callback, result_callback);
  } catch(e) {
    form.submit.disabled = false;
    alert('ERROR: ' + e.message);
    return;
  }

  passforge.pwgen(form.password.value,
          form.nickname.value,
          form.progress.checked);
}
