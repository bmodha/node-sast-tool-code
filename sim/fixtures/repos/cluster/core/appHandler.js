const db = {};

module.exports.modifyProduct = function (req, res) {
  db.Product.find({
    where: {
      'id': req.query.id
    }
  }).then(product => {
    res.render('app/modifyproduct', {
      output: { product: product }
    })
  })
}

module.exports.modifyProductSubmit = function (req, res) {
  db.Product.find({
    where: {
      'id': req.body.id
    }
  }).then(product => {
    product.name = req.body.name
    product.save()
  })
}

// gap-between-copies

module.exports.userEditSubmit = function (req, res) {
  db.User.find({
    where: {
      'id': req.body.id
    }
  }).then(user => {
    user.name = req.body.name
    user.save()
  })
}
