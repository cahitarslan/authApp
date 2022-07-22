const { validationResult } = require('express-validator');
const User = require('../model/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const loginFormunuGoster = (req, res, next) => {
    res.render('login', { layout: './layout/auth_layout', title: 'Giriş Yap' });
};

const login = (req, res, next) => {
    const hatalar = validationResult(req);

    req.flash('email', req.body.email);
    req.flash('sifre', req.body.sifre);

    if (!hatalar.isEmpty()) {
        req.flash('validation_error', hatalar.array());
        res.redirect('/login');
    } else {
        passport.authenticate('local', {
            successRedirect: '/yonetim',
            failureRedirect: '/login',
            failureFlash: true,
        })(req, res, next);
    }
};

const registerFormunuGoster = (req, res, next) => {
    res.render('register', { layout: './layout/auth_layout', title: 'Kayıt Ol' });
};

const register = async (req, res, next) => {
    const hatalar = validationResult(req);
    if (!hatalar.isEmpty()) {
        // res.render('register', { layout: './layout/auth_layout', hatalar: hatalar.array() });
        req.flash('validation_error', hatalar.array());
        req.flash('email', req.body.email);
        req.flash('ad', req.body.ad);
        req.flash('soyad', req.body.soyad);
        req.flash('sifre', req.body.sifre);
        req.flash('resifre', req.body.resifre);

        res.redirect('/register');
    } else {
        try {
            const _user = await User.findOne({ email: req.body.email });

            if (_user && _user.emailAktif == true) {
                req.flash('validation_error', [{ msg: 'Bu mail kullanımda' }]);
                req.flash('email', req.body.email);
                req.flash('ad', req.body.ad);
                req.flash('soyad', req.body.soyad);
                req.flash('sifre', req.body.sifre);
                req.flash('resifre', req.body.resifre);
                res.redirect('/register');
            } else if ((_user && _user.emailAktif == false) || _user == null) {
                if (_user) {
                    await User.findByIdAndRemove({ _id: _user._id });
                }
                const newUser = new User({
                    email: req.body.email,
                    ad: req.body.ad,
                    soyad: req.body.soyad,
                    sifre: await bcrypt.hash(req.body.sifre, 10),
                });
                await newUser.save();

                //jwt işlemleri
                const jwtBilgileri = {
                    id: newUser.id,
                    mail: newUser.email,
                };

                const jwtToken = jwt.sign(jwtBilgileri, process.env.CONFIRM_MAIL_JWT_SECRET, { expiresIn: '1d' });

                console.log(jwtToken);

                //mail gönderme işlemleri
                const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;

                console.log('gidilecek url = ' + url);

                let transporter = nodemailer.createTransport({
                    host: 'smtp.ethereal.email',
                    port: 587,
                    secure: false,
                    auth: {
                        user: process.env.GMAIL_USER,
                        pass: process.env.GMAIL_SIFRE,
                    },
                });

                await transporter.sendMail(
                    {
                        from: '"Nodejs Uygulaması" <rebeka.krajcik18@ethereal.email>',
                        to: newUser.email,
                        subject: 'Emailinizi Lütfen Onaylayın',
                        text: 'Emailinizi onaylamak için lütfen şu linki tıklayın: ' + url,
                    },
                    (error, info) => {
                        if (error) {
                            console.log('bir hata var ' + error);
                        }
                        console.log('Mail gönderildi');
                        console.log(info);
                        transporter.close();
                    }
                );

                req.flash('success_message', [{ msg: 'Lütfen mail kutunuzu kontrol edin' }]);
                res.redirect('/login');
            }
        } catch (error) {
            console.log('Kullanıcı kaydedilirken hata çıktı: ' + error);
        }
    }
};

const forgetPasswordFormunuGoster = (req, res, next) => {
    res.render('forget_password', { layout: './layout/auth_layout', title: 'Şifremi Unuttum' });
};

const forgetPassword = async (req, res, next) => {
    const hatalar = validationResult(req);

    if (!hatalar.isEmpty()) {
        // res.render('register', { layout: './layout/auth_layout', hatalar: hatalar.array() });
        req.flash('validation_error', hatalar.array());
        req.flash('email', req.body.email);

        res.redirect('/forget-password');
    }
    // burası çalışıyorsa kullanıcı düzgün bir mail girmiştir
    else {
        try {
            const _user = await User.findOne({ email: req.body.email, emailAktif: true });

            if (_user) {
                // kullanıcıya şifre sıfırlama maili atılabilir
                const jwtBilgileri = {
                    id: _user._id,
                    mail: _user.email,
                };
                const secret = process.env.RESET_PASSWORD_JWT_SECRET + '-' + _user.sifre;
                const jwtToken = jwt.sign(jwtBilgileri, secret, { expiresIn: '1d' });

                const url = process.env.WEB_SITE_URL + 'reset-password/' + _user._id + '/' + jwtToken;

                let transporter = nodemailer.createTransport({
                    host: 'smtp.ethereal.email',
                    port: 587,
                    secure: false,
                    auth: {
                        user: process.env.GMAIL_USER,
                        pass: process.env.GMAIL_SIFRE,
                    },
                });

                await transporter.sendMail(
                    {
                        from: '"Nodejs Uygulaması" <loyce.harber36@ethereal.email>',
                        to: _user.email,
                        subject: 'Şifre Sıfırlama',
                        text: 'Şifrenizi oluşturmak için lütfen şu linki tıklayın: ' + url,
                    },
                    (error, info) => {
                        if (error) {
                            console.log('bir hata var ' + error);
                        }
                        console.log('Mail gönderildi');
                        console.log(info);
                        transporter.close();
                    }
                );

                req.flash('success_message', [{ msg: 'Lütfen mail kutunuzu kontrol edin' }]);
                res.redirect('/login');
            } else {
                req.flash('validation_error', [{ msg: 'Bu mail kayıtlı değil veya kullanıcı pasif' }]);
                req.flash('email', req.body.email);
                res.redirect('forget-password');
            }
        } catch (error) {
            console.log('Kullanıcı kaydedilirken hata çıktı: ' + error);
        }
    }
};

const logout = (req, res, next) => {
    req.logout();
    req.session.destroy((err) => {
        res.clearCookie('connect.sid');
        // req.flash('success_message', [{ msg: 'Başarıyla çıkış yapıldı' }]);
        // res.redirect('/login');
        res.render('login', { layout: './layout/auth_layout', title: 'Giriş Yap', success_message: [{ msg: 'Başarıyla çıkış yapıldı' }] });
        // res.send('Çıkış yapıldı');
    });
};

const verifyMail = (req, res, next) => {
    const token = req.query.id;
    if (token) {
        try {
            jwt.verify(token, process.env.CONFIRM_MAIL_JWT_SECRET, async (e, decoded) => {
                if (e) {
                    req.flash('error', 'Kod hatalı veya süresi geçmiş');
                    res.redirect('/login');
                } else {
                    const tokenIcindekiIdDegeri = decoded.id;
                    const sonuc = await User.findByIdAndUpdate(tokenIcindekiIdDegeri, { emailAktif: true });

                    if (sonuc) {
                        req.flash('success_message', [{ msg: 'Başarıyla mail onaylandı' }]);
                        res.redirect('/login');
                    } else {
                        req.flash('error', 'Lütfen tekrar kullanıcı oluşturun');
                        res.redirect('/login');
                    }
                }
            });
        } catch (error) {}
    } else {
        req.flash('error', 'Token yok veya geçersiz');
        res.redirect('/login');
    }
};

const yeniSifreFormuGoster = async (req, res, next) => {
    const linktekiId = req.params.id;
    const linktekiToken = req.params.token;

    if (linktekiId && linktekiToken) {
        const _bulunanUser = await User.findOne({ _id: linktekiId });

        const secret = process.env.RESET_PASSWORD_JWT_SECRET + '-' + _bulunanUser.sifre;

        try {
            jwt.verify(linktekiToken, secret, async (e, decoded) => {
                if (e) {
                    req.flash('error', 'Kod hatalı veya süresi geçmiş');
                    res.redirect('/forget-password');
                } else {
                    res.render('new_password', { id: linktekiId, token: linktekiToken, layout: './layout/auth_layout', title: 'Şifre Güncelle' });

                    // const tokenIcindekiIdDegeri = decoded.id;
                    // const sonuc = await User.findByIdAndUpdate(tokenIcindekiIdDegeri, { emailAktif: true });

                    // if (sonuc) {
                    //     req.flash('success_message', [{ msg: 'Başarıyla mail onaylandı' }]);
                    //     res.redirect('/login');
                    // } else {
                    //     req.flash('error', 'Lütfen tekrar kullanıcı oluşturun');
                    //     res.redirect('/login');
                    // }
                }
            });
        } catch (error) {}
    } else {
        req.flash('validation_error', [{ msg: 'Lütfen maildeki linki tıklayın. Token bulunamadı' }]);
        res.redirect('forget-password');
    }
};

const yeniSifreyiKaydet = async (req, res, next) => {
    const hatalar = validationResult(req);

    if (!hatalar.isEmpty()) {
        // res.render('register', { layout: './layout/auth_layout', hatalar: hatalar.array() });
        req.flash('validation_error', hatalar.array());
        req.flash('sifre', req.body.sifre);
        req.flash('resifre', req.body.resifre);

        console.log('formdan gelen değerler');
        console.log(req.body);

        res.redirect('/reset-password/' + req.body.id + '/' + req.body.token);
    } else {
        const _bulunanUser = await User.findOne({ _id: req.body.id, emailAktif: true });

        const secret = process.env.RESET_PASSWORD_JWT_SECRET + '-' + _bulunanUser.sifre;

        try {
            jwt.verify(req.body.token, secret, async (e, decoded) => {
                if (e) {
                    req.flash('error', 'Kod hatalı veya süresi geçmiş');
                    res.redirect('/forget-password');
                } else {
                    //yeni şifreyi kaydet
                    const hashedPassword = await bcrypt.hash(req.body.sifre, 10);
                    const sonuc = await User.findByIdAndUpdate(req.body.id, { sifre: hashedPassword });

                    if (sonuc) {
                        req.flash('success_message', [{ msg: 'Şifre başarıyla güncellendi' }]);
                        res.redirect('/login');
                    } else {
                        req.flash('error', 'Lütfen tekrar şifre sıfırlama adımlarını yapın oluşturun');
                        res.redirect('/login');
                    }
                }
            });
        } catch (error) {
            console.log('hata çıktı: ' + error);
        }
    }
};

module.exports = {
    loginFormunuGoster,
    registerFormunuGoster,
    forgetPasswordFormunuGoster,
    register,
    login,
    forgetPassword,
    logout,
    verifyMail,
    yeniSifreFormuGoster,
    yeniSifreyiKaydet,
};
