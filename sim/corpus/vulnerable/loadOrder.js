function loadOrder(orderId) {
  const query = "SELECT * FROM orders WHERE id = " + orderId;
  return query;
}
