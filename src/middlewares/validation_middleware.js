const { body } = require('express-validator');

const validateNewUser = () => {
    return [
        body('email').trim().isEmail().withMessage('Geçerli bir mail giriniz'),
        body('sifre')
            .trim()
            .isLength({ min: 6 })
            .withMessage('Parola en az 6 karakter olmalıdır')
            .isLength({ max: 20 })
            .withMessage('Parola en fazla 20 karakter olmalıdır'),
        body('ad')
            .trim()
            .isLength({ min: 2 })
            .withMessage('İsim en az 2 karakter olmalıdır')
            .isLength({ max: 30 })
            .withMessage('İsim en fazla 30 karakter olmalıdır'),
        body('soyad')
            .trim()
            .isLength({ min: 2 })
            .withMessage('Soyisim en az 2 karakter olmalıdır')
            .isLength({ max: 30 })
            .withMessage('Soyisim en fazla 30 karakter olmalıdır'),
        body('resifre')
            .trim()
            .custom((value, { req }) => {
                if (value !== req.body.sifre) {
                    throw new Error('Şifreler aynı değil');
                }
                return true;
            }),
    ];
};

const validateLogin = () => {
    return [
        body('email').trim().isEmail().withMessage('Geçerli bir mail giriniz'),
        body('sifre')
            .trim()
            .isLength({ min: 6 })
            .withMessage('Parola en az 6 karakter olmalıdır')
            .isLength({ max: 20 })
            .withMessage('Parola en fazla 20 karakter olmalıdır'),
    ];
};

const validateEmail = () => {
    return [body('email').trim().isEmail().withMessage('Geçerli bir mail giriniz')];
};

const validateNewPassword = () => {
    return [
        body('sifre')
            .trim()
            .isLength({ min: 6 })
            .withMessage('Parola en az 6 karakter olmalıdır')
            .isLength({ max: 20 })
            .withMessage('Parola en fazla 20 karakter olmalıdır'),

        body('resifre')
            .trim()
            .custom((value, { req }) => {
                if (value !== req.body.sifre) {
                    throw new Error('Şifreler aynı değil');
                }
                return true;
            }),
    ];
};

module.exports = {
    validateNewUser,
    validateLogin,
    validateEmail,
    validateNewPassword,
};
