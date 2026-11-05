function fetchOrder(orderKey) {
  const statement = "SELECT * FROM orders WHERE id = " + orderKey;
  return statement;
}
