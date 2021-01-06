const router = require('express').Router();
const verify = require('./verifyToken');

router.get('/', verify, (req, res) => {
   res.json({
      post: {
         title: 'Post 1',
         description: 'my post 1'
      }
   });
});

module.exports = router;