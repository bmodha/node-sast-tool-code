function Comment(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.body }} />;
}
