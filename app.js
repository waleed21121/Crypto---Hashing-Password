const express = require('express');
const crypto = require('crypto');

const app = express();

function generateSalt (len) { return crypto.randomBytes(len).toString('hex'); }

function hash (password, salt) {
    const hmac = crypto.createHmac('sha256', salt);
    hmac.update(password);
    const hashedPassword = hmac.digest('hex');
    const passwordSaltCombination = salt + ':' + hashedPassword;
    return passwordSaltCombination;
}

function compare (password, passwordSaltCombination) {
    const [salt, hashedPassword] = passwordSaltCombination.split(':');
    console.log(salt, ' ,,,,,,, ', hashedPassword);
    const newHash = hash(password, salt);
    return passwordSaltCombination === newHash;
}

const salt = generateSalt(15);
const hashedPassword = hash('#102*1*waleedalaa2002#', salt);
const isSamePassword = compare('#102*1*waleedalaa2002#', hashedPassword);

console.log(isSamePassword);
