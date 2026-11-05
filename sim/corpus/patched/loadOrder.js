function loadOrder(orderId) {
  return queryWithBinding("SELECT * FROM orders WHERE id = $1", [orderId]);
}
