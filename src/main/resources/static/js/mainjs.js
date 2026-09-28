$(document).ready(function () {

    // ===== Trang profile: hiển thị thông tin người dùng đăng nhập =====
    if ($('#profile').length) {
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            beforeSend: function (xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function (data) {
                $('#profile').html(data.fullName);
                $('#images').attr('src', data.images);
            },
            error: function () {
                alert('Sorry, you are not logged in.');
                window.location.href = '/login';
            }
        });
    }

    // ===== Đăng xuất =====
    $('#logout').click(function () {
        localStorage.clear();
        window.location.href = '/login';
    });

    // ===== Đăng nhập =====
    $('#Login').click(function () {
        var basicInfo = JSON.stringify({
            email: document.getElementById('email').value,
            password: document.getElementById('password').value
        });
        $.ajax({
            type: 'POST',
            url: '/auth/login',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: basicInfo,
            success: function (data) {
                localStorage.token = data.token;
                window.location.href = '/user/profile';
            },
            error: function () {
                alert('Login Failed');
            }
        });
    });
});
