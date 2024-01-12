document.querySelector('.menu-icon')
.addEventListener('click', function() {
    let box = document.querySelector('.hidden-box')
    if (window.getComputedStyle(box).visibility === 'hidden') {
        box.style.visibility = 'visible';
    } else {
        box.style.visibility = 'hidden';
    }
});
